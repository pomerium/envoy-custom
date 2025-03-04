#pragma once

#include <memory>

#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/recorder.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;

class SessionRecordingFilter : public StreamFilter, public Logger::Loggable<Logger::Id::filter> {
public:
  SessionRecordingFilter(Api::Api& api, std::shared_ptr<Config> config)
      : api_(api), config_(config), recorder_(std::make_unique<SessionRecorder>(config)) {
  }
  void onDestroy() override {
    recorder_->stopOnce();
  }

  void setDecoderFilterCallbacks(DecoderFilterCallback& callbacks) override {
    decoder_callbacks_ = &callbacks;
  }
  void setEncoderFilterCallbacks(EncoderFilterCallback& callbacks) override {
    encoder_callbacks_ = &callbacks;
  }
  bool filterEnabled(const envoy::config::core::v3::Metadata&) {
    return true;
  }
  HeaderFilterStatus decodeHeaderFrame(RequestHeaderFrame& frame) override {
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
  CommonFilterStatus decodeCommonFrame(RequestCommonFrame& frame) override {
    // this downcast is safe; SSHRequestCommonFrame is the only implementation of RequestCommonFrame
    auto& sshFrame = static_cast<const Codec::SSHRequestCommonFrame&>(frame);
    recorder_->handleDownstreamToUpstreamMessage(sshFrame.message());
    return CommonFilterStatus::Continue;
  }
  HeaderFilterStatus encodeHeaderFrame(ResponseHeaderFrame& frame) override {
    if (frame.frameFlags().endStream()) {
      auto& sshFrame = static_cast<const Codec::SSHResponseHeaderFrame&>(frame);
      recorder_->onStreamEnd(sshFrame);
    }
    return HeaderFilterStatus::Continue;
  };
  CommonFilterStatus encodeCommonFrame(ResponseCommonFrame& frame) override {
    auto& sshFrame = static_cast<const Codec::SSHResponseCommonFrame&>(frame);
    recorder_->handleUpstreamToDownstreamMessage(sshFrame.message());
    return CommonFilterStatus::Continue;
  };

private:
  absl::Status initializeRecording(RequestHeaderFrame& frame) {
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
    auto file = api_.fileSystem().createFile(Filesystem::FilePathAndType(Filesystem::DestinationType::File, filename));
    if (auto err = file->open(1 << Filesystem::File::Operation::Write |
                              1 << Filesystem::File::Operation::Create);
        !err.ok()) {
      ENVOY_LOG(error, "error opening recording file {} for reading: {}", file->path(), err.err_->getErrorDetails());
      return absl::InternalError("internal error");
    }

    return recorder_->onStreamBegin(sshFrame, std::move(file));
  }

  Api::Api& api_;
  std::shared_ptr<Config> config_;
  DecoderFilterCallback* decoder_callbacks_;
  EncoderFilterCallback* encoder_callbacks_;
  std::unique_ptr<SessionRecorder> recorder_;
};

class SessionRecordingFilterFactory : public NamedFilterConfigFactory {

public:
  FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& config, const std::string&,
                               Server::Configuration::FactoryContext& ctx) override {
    auto conf = std::make_shared<Config>(dynamic_cast<const Config&>(config));

    return [&ctx, conf](FilterChainFactoryCallbacks& callbacks) {
      callbacks.addFilter(std::make_shared<SessionRecordingFilter>(ctx.serverFactoryContext().api(), conf));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Config>();
  }
  ProtobufTypes::MessagePtr createEmptyRouteConfigProto() override { return nullptr; }
  RouteSpecificFilterConfigConstSharedPtr
  createRouteSpecificFilterConfig(const Protobuf::Message&,
                                  Server::Configuration::ServerFactoryContext&,
                                  ProtobufMessage::ValidationVisitor&) override {
    return nullptr;
  }
  bool isTerminalFilter() override { return false; }

  std::string name() const override { return "envoy.filters.generic.ssh.session_recording"; }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording