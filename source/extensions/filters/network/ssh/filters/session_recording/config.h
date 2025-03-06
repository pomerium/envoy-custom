#pragma once

#include <memory>

#pragma clang unsafe_buffer_usage begin
#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/filters/session_recording/recorder.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;

class SessionRecordingFilter : public StreamFilter, public Logger::Loggable<Logger::Id::filter> {
public:
  SessionRecordingFilter(Api::Api& api, std::shared_ptr<Config> config);
  void onDestroy() override;

  void setDecoderFilterCallbacks(DecoderFilterCallback& callbacks) override;
  void setEncoderFilterCallbacks(EncoderFilterCallback& callbacks) override;
  HeaderFilterStatus decodeHeaderFrame(RequestHeaderFrame& frame) override;
  CommonFilterStatus decodeCommonFrame(RequestCommonFrame& frame) override;
  HeaderFilterStatus encodeHeaderFrame(ResponseHeaderFrame& frame) override;
  CommonFilterStatus encodeCommonFrame(ResponseCommonFrame& frame) override;

private:
  absl::Status initializeRecording(RequestHeaderFrame& frame);

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
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording