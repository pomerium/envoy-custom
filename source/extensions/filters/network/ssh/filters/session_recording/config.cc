#include "source/extensions/filters/network/ssh/filters/session_recording/config.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/admin_api.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "envoy/compression/compressor/config.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/grpc/async_client_impl.h"
#include "source/common/config/utility.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

SessionRecordingFilter::SessionRecordingFilter(
  Api::Api& api,
  std::shared_ptr<Config> config,
  std::shared_ptr<RecordingUploader> uploader)
    : api_(api),
      config_(config),
      recorder_(std::make_unique<SessionRecorder>(config, *this)),
      uploader_(uploader) {}

void SessionRecordingFilter::onDestroy() {
  recorder_ = nullptr;
  decoder_callbacks_ = nullptr;
  encoder_callbacks_ = nullptr;
}

void SessionRecordingFilter::setDecoderFilterCallbacks(DecoderFilterCallback& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void SessionRecordingFilter::setEncoderFilterCallbacks(EncoderFilterCallback& callbacks) {
  encoder_callbacks_ = &callbacks;
}

HeaderFilterStatus SessionRecordingFilter::decodeHeaderFrame(RequestHeaderFrame& frame) {
  auto stat = initializeRecording(frame);
  if (!stat.ok()) {
    decoder_callbacks_->dispatcher().post([cb = decoder_callbacks_, stat] {
      // NB: the message in the status passed to sendLocalReply (first argument) cannot contain
      // spaces. We only send the code with an empty message; the original message is passed
      // separately as optional string data, and read in ServerCodec::respond()
      cb->sendLocalReply(absl::Status(stat.code(), ""), stat.message()); // this will end the stream
    });
    return HeaderFilterStatus::StopIteration;
  }
  return HeaderFilterStatus::Continue;
}

CommonFilterStatus SessionRecordingFilter::decodeCommonFrame(RequestCommonFrame& frame) {
  if (!enabled_) {
    return CommonFilterStatus::Continue;
  }
  // this downcast is safe; SSHRequestCommonFrame is the only implementation of RequestCommonFrame
  auto& sshFrame = static_cast<const Codec::SSHRequestCommonFrame&>(frame);
  recorder_->handleDownstreamToUpstreamMessage(sshFrame.message());
  return CommonFilterStatus::Continue;
}

HeaderFilterStatus SessionRecordingFilter::encodeHeaderFrame(ResponseHeaderFrame& frame) {
  if (!enabled_) {
    return HeaderFilterStatus::Continue;
  }
  if (frame.frameFlags().endStream()) {
    auto& sshFrame = static_cast<const Codec::SSHResponseHeaderFrame&>(frame);
    recorder_->onStreamEnd(sshFrame);
  }
  return HeaderFilterStatus::Continue;
};

CommonFilterStatus SessionRecordingFilter::encodeCommonFrame(ResponseCommonFrame& frame) {
  if (!enabled_) {
    return CommonFilterStatus::Continue;
  }
  auto& sshFrame = static_cast<const Codec::SSHResponseCommonFrame&>(frame);
  recorder_->handleUpstreamToDownstreamMessage(sshFrame.message());
  return CommonFilterStatus::Continue;
};

absl::Status SessionRecordingFilter::initializeRecording(RequestHeaderFrame& frame) {
  // this downcast is safe; SSHRequestHeaderFrame is the only implementation of RequestHeaderFrame
  const auto& sshFrame = static_cast<const Codec::SSHRequestHeaderFrame&>(frame);
  const auto& state = sshFrame.authState();
  if (!state->allow_response) {
    return absl::InternalError("failed to initialize filter: missing AllowResponse in auth state");
  }
  if (!state->allow_response->has_upstream()) {
    return absl::InternalError("failed to initialize filter: upstream not set");
  }
  bool shouldRecord{false};
  std::string recording_name;
  pomerium::extensions::ssh::filters::session_recording::Format recording_format{};
  for (const auto& ext : state->allow_response->upstream().extensions()) {
    if (ext.has_typed_config()) {
      const auto& typedConfig = ext.typed_config();
      if (typedConfig.Is<UpstreamTargetExtensionConfig>()) {
        UpstreamTargetExtensionConfig cfg;
        if (!typedConfig.UnpackTo(&cfg)) {
          return absl::InternalError("error decoding UpstreamTargetExtensionConfig in AllowResponse");
        }
        shouldRecord = true;
        recording_name = cfg.recording_name();
        recording_format = cfg.format();
        if (absl::StrContains(recording_name, "/")) {
          return absl::InternalError("failed to initialize session recording: invalid character '/' in filename");
        }
        break;
      }
    }
  }
  enabled_ = shouldRecord;
  if (!enabled_) {
    return absl::OkStatus();
  }

  auto filename = absl::StrJoin({config_->storage_dir(), recording_name}, "/");
  // createFile doesn't actually create the file on disk, interestingly enough. It is created by
  // passing the Create flag to open().
  auto file = api_.fileSystem().createFile(
    Filesystem::FilePathAndType(Filesystem::DestinationType::File, filename));
  if (auto err = file->open(1 << Filesystem::File::Operation::Write |
                            1 << Filesystem::File::Operation::Create);
      !err.ok()) {
    ENVOY_LOG(error, "error opening recording file {} for reading: {}",
              file->path(), err.err_->getErrorDetails());
    return absl::InternalError("internal error");
  }
  return recorder_->onStreamBegin(sshFrame, std::move(file), recording_format, decoder_callbacks_->dispatcher());
}

FilterFactoryCb
SessionRecordingFilterFactory::createFilterFactoryFromProto(const Protobuf::Message& config,
                                                            const std::string&,
                                                            Server::Configuration::FactoryContext& ctx) {
  auto conf = std::make_shared<Config>(dynamic_cast<const Config&>(config));
  auto admin_api = std::make_shared<AdminApi>(conf, ctx);

  const std::string type{TypeUtil::typeUrlToDescriptorFullName(
    conf->compressor_library().typed_config().type_url())};
  auto* config_factory = Registry::FactoryRegistry<
    Compression::Compressor::NamedCompressorLibraryConfigFactory>::getFactoryByType(type);
  if (config_factory == nullptr) {
    throw Envoy::EnvoyException(
      fmt::format("Didn't find a registered implementation for type: '{}'", type));
  }
  ProtobufTypes::MessagePtr message = Envoy::Config::Utility::translateAnyToFactoryConfig(
    conf->compressor_library().typed_config(), ctx.messageValidationVisitor(),
    *config_factory);
  auto compressor_factory = config_factory->createCompressorFactoryFromProto(*message, ctx);

  auto createGrpcClient = [&ctx, conf]() {
    return Grpc::AsyncClientImpl::create(ctx.serverFactoryContext().clusterManager(),
                                         conf->grpc_service(), ctx.serverFactoryContext().timeSource());
  };
  upload_thread_dispatcher_ = &ctx.serverFactoryContext()
                                 .clusterManager()
                                 .getThreadLocalCluster(conf->grpc_service().envoy_grpc().cluster_name())
                                 ->httpAsyncClient()
                                 .dispatcher();
  auto uploader = std::make_shared<RecordingUploader>(conf, ctx.serverFactoryContext().api().fileSystem(),
                                                      *upload_thread_dispatcher_, createGrpcClient,
                                                      std::move(compressor_factory));

  return [&ctx, conf, admin_api, uploader](FilterChainFactoryCallbacks& callbacks) {
    auto filter = std::make_shared<SessionRecordingFilter>(ctx.serverFactoryContext().api(), conf, uploader);
    callbacks.addFilter(filter);
  };
}

ProtobufTypes::MessagePtr SessionRecordingFilterFactory::createEmptyConfigProto() {
  return std::make_unique<Config>();
}

REGISTER_FACTORY(SessionRecordingFilterFactory, NamedFilterConfigFactory);

void SessionRecordingFilter::finalize(RecordingMetadata metadata) {
  uploader_->upload(std::move(metadata));
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording