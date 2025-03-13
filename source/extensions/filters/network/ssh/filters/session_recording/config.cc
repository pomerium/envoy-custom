#include "source/extensions/filters/network/ssh/filters/session_recording/config.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/admin_api.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

SessionRecordingFilter::SessionRecordingFilter(Api::Api& api, std::shared_ptr<Config> config)
    : api_(api), config_(config), recorder_(std::make_unique<SessionRecorder>(config)) {
}

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
  if (!enabled_) {
    return HeaderFilterStatus::Continue;
  }
  auto stat = initializeRecording(frame);
  if (!stat.ok()) {
    decoder_callbacks_->dispatcher().post([this, stat] {
      // NB: the message in the status passed to sendLocalReply (first argument) cannot contain
      // spaces. We only send the code with an empty message; the original message is passed
      // separately as optional string data, and read in ServerCodec::respond()
      decoder_callbacks_->sendLocalReply(absl::Status(stat.code(), ""), stat.message());
      decoder_callbacks_->completeDirectly();
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
  for (const auto& ext : state->allow_response->upstream().extensions()) {
    if (ext.has_typed_config()) {
      const auto& typedConfig = ext.typed_config();
      if (typedConfig.Is<UpstreamTargetExtensionConfig>()) {
        UpstreamTargetExtensionConfig cfg;
        if (!typedConfig.UnpackTo(&cfg)) {
          return absl::InternalError("error decoding UpstreamTargetExtensionConfig in AllowResponse");
        }
        shouldRecord = cfg.record_session();
        break;
      }
    }
  }
  enabled_ = shouldRecord;
  if (!enabled_) {
    return absl::OkStatus();
  }

  auto filename = fmt::format("{}/session-{}-at-{}-{}.cast",
                              config_->access_log_storage_dir(),
                              state->allow_response->username(),
                              state->allow_response->upstream().hostname(),
                              absl::ToUnixNanos(absl::Now()));
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
  return recorder_->onStreamBegin(sshFrame, std::move(file), decoder_callbacks_->dispatcher());
}

FilterFactoryCb
SessionRecordingFilterFactory::createFilterFactoryFromProto(const Protobuf::Message& config,
                                                            const std::string&,
                                                            Server::Configuration::FactoryContext& ctx) {
  auto conf = std::make_shared<Config>(dynamic_cast<const Config&>(config));
  auto admin_api = std::make_shared<AdminApi>(conf, ctx);

  return [&ctx, conf, admin_api = admin_api](FilterChainFactoryCallbacks& callbacks) {
    auto filter = std::make_shared<SessionRecordingFilter>(ctx.serverFactoryContext().api(), conf);
    callbacks.addFilter(filter);
  };
}

ProtobufTypes::MessagePtr SessionRecordingFilterFactory::createEmptyConfigProto() {
  return std::make_unique<Config>();
}

REGISTER_FACTORY(SessionRecordingFilterFactory, NamedFilterConfigFactory);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording