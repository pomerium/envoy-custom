#pragma once

#include <memory>

#pragma clang unsafe_buffer_usage begin
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
#pragma clang diagnostic pop
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/filters/session_recording/recorder.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/uploader.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;
using pomerium::extensions::ssh::filters::session_recording::RecordingData;
using pomerium::extensions::ssh::filters::session_recording::RecordingMetadata;
using pomerium::extensions::ssh::filters::session_recording::UpstreamTargetExtensionConfig;

class SessionRecordingFilter : public StreamFilter,
                               public SessionRecordingCallbacks,
                               public Logger::Loggable<Logger::Id::filter> {
public:
  SessionRecordingFilter(Api::Api& api, std::shared_ptr<Config> config, std::shared_ptr<RecordingUploader> uploader);
  void onDestroy() override;

  void setDecoderFilterCallbacks(DecoderFilterCallback& callbacks) override;
  void setEncoderFilterCallbacks(EncoderFilterCallback& callbacks) override;
  HeaderFilterStatus decodeHeaderFrame(RequestHeaderFrame& frame) override;
  CommonFilterStatus decodeCommonFrame(RequestCommonFrame& frame) override;
  HeaderFilterStatus encodeHeaderFrame(ResponseHeaderFrame& frame) override;
  CommonFilterStatus encodeCommonFrame(ResponseCommonFrame& frame) override;

  void finalize(RecordingMetadata metadata) override;

private:
  absl::Status initializeRecording();
  bool enabled_{false};
  Api::Api& api_;
  std::shared_ptr<Config> config_;
  std::weak_ptr<Codec::AuthState> auth_state_;
  DecoderFilterCallback* decoder_callbacks_;
  EncoderFilterCallback* encoder_callbacks_;
  std::unique_ptr<SessionRecorder> recorder_;
  std::shared_ptr<RecordingUploader> uploader_;
};

class SessionRecordingFilterFactory : public NamedFilterConfigFactory, public Logger::Loggable<Logger::Id::filter> {
public:
  FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& config, const std::string&,
                               Server::Configuration::FactoryContext& ctx) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  ProtobufTypes::MessagePtr createEmptyRouteConfigProto() override { return nullptr; }
  RouteSpecificFilterConfigConstSharedPtr
  createRouteSpecificFilterConfig(const Protobuf::Message&,
                                  Server::Configuration::ServerFactoryContext&,
                                  ProtobufMessage::ValidationVisitor&) override {
    return nullptr;
  }
  bool isTerminalFilter() override { return false; }
  std::string name() const override { return "envoy.filters.generic.ssh.session_recording"; }

private:
  void startUploadThread(Server::Configuration::FactoryContext& ctx);
  Envoy::Event::Dispatcher* upload_thread_dispatcher_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording