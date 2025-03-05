#include "source/extensions/filters/network/ssh/filters/session_recording/config.h"

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
  // this downcast is safe; SSHRequestCommonFrame is the only implementation of RequestCommonFrame
  auto& sshFrame = static_cast<const Codec::SSHRequestCommonFrame&>(frame);
  recorder_->handleDownstreamToUpstreamMessage(sshFrame.message());
  return CommonFilterStatus::Continue;
}

HeaderFilterStatus SessionRecordingFilter::encodeHeaderFrame(ResponseHeaderFrame& frame) {
  if (frame.frameFlags().endStream()) {
    auto& sshFrame = static_cast<const Codec::SSHResponseHeaderFrame&>(frame);
    recorder_->onStreamEnd(sshFrame);
  }
  return HeaderFilterStatus::Continue;
};

CommonFilterStatus SessionRecordingFilter::encodeCommonFrame(ResponseCommonFrame& frame) {
  auto& sshFrame = static_cast<const Codec::SSHResponseCommonFrame&>(frame);
  recorder_->handleUpstreamToDownstreamMessage(sshFrame.message());
  return CommonFilterStatus::Continue;
};

absl::Status SessionRecordingFilter::initializeRecording(RequestHeaderFrame& frame) {
  // this downcast is safe; SSHRequestHeaderFrame is the only implementation of RequestHeaderFrame
  const auto& sshFrame = static_cast<const Codec::SSHRequestHeaderFrame&>(frame);
  const auto& state = sshFrame.authState();
  auto filename = fmt::format("{}/session-{}-at-{}-{}.cast",
                              config_->access_log_storage_dir(),
                              state->username,
                              state->hostname,
                              state->stream_id);
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

  return recorder_->onStreamBegin(sshFrame, std::move(file));
}

FilterFactoryCb
SessionRecordingFilterFactory::createFilterFactoryFromProto(const Protobuf::Message& config,
                                                            const std::string&,
                                                            Server::Configuration::FactoryContext& ctx) {
  auto conf = std::make_shared<Config>(dynamic_cast<const Config&>(config));

  return [&ctx, conf](FilterChainFactoryCallbacks& callbacks) {
    callbacks.addFilter(std::make_shared<SessionRecordingFilter>(
      ctx.serverFactoryContext().api(), conf));
  };
}

ProtobufTypes::MessagePtr SessionRecordingFilterFactory::createEmptyConfigProto() {
  return std::make_unique<Config>();
}

REGISTER_FACTORY(SessionRecordingFilterFactory, NamedFilterConfigFactory);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording