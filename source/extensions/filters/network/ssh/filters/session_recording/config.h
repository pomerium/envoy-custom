#pragma once

#include <memory>
#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;

class SessionRecordingFilter : public StreamFilter, public Logger::Loggable<Logger::Id::filter> {
public:
  SessionRecordingFilter(std::shared_ptr<Config> config)
      : config_(config) {
  }
  void onDestroy() override {}

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
    auto& sshFrame = dynamic_cast<const Codec::SSHRequestHeaderFrame&>(frame);
    (void)sshFrame;
    ENVOY_LOG(debug, "decodeHeaderFrame");
    return HeaderFilterStatus::Continue;
  }
  CommonFilterStatus decodeCommonFrame(RequestCommonFrame& frame) override {
    auto& sshFrame = dynamic_cast<const Codec::SSHRequestCommonFrame&>(frame);
    ENVOY_LOG(debug, "decodeCommonFrame: {}", sshFrame.message().msg_type());
    return CommonFilterStatus::Continue;
  }
  HeaderFilterStatus encodeHeaderFrame(ResponseHeaderFrame& frame) override {
    auto& sshFrame = dynamic_cast<const Codec::SSHResponseHeaderFrame&>(frame);

    ENVOY_LOG(debug, "encodeHeaderFrame: {}", sshFrame.message().msg_type());
    return HeaderFilterStatus::Continue;
  };
  CommonFilterStatus encodeCommonFrame(ResponseCommonFrame& frame) override {
    auto& sshFrame = dynamic_cast<const Codec::SSHResponseCommonFrame&>(frame);

    ENVOY_LOG(debug, "encodeCommonFrame: {}", sshFrame.message().msg_type());
    return CommonFilterStatus::Continue;
  };

private:
  std::shared_ptr<Config> config_;
  DecoderFilterCallback* decoder_callbacks_;
  EncoderFilterCallback* encoder_callbacks_;
};

class SessionRecordingFilterFactory : public NamedFilterConfigFactory {

public:
  FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& config, const std::string&,
                               Server::Configuration::FactoryContext&) override {
    auto conf = std::make_shared<Config>(dynamic_cast<const Config&>(config));

    return [conf](FilterChainFactoryCallbacks& callbacks) {
      callbacks.addFilter(std::make_shared<SessionRecordingFilter>(conf));
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