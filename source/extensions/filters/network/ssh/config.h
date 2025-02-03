#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "validate/validate.h"
#include <cerrno>
#include <unistd.h>

#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/session.h"
#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
class SshCodecFactoryConfig : public CodecFactoryConfig {
public:
  // CodecFactoryConfig
  CodecFactoryPtr
  createCodecFactory(const Protobuf::Message& config,
                     Envoy::Server::Configuration::ServerFactoryContext& context) override;
  std::string name() const override { return "envoy.generic_proxy.codecs.ssh"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<pomerium::extensions::SshCodecConfig>();
  }
};

class SshClientCodec : public ClientCodec {
public:
  SshClientCodec() = default;
  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override {
    (void)callbacks;
  }
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override {
    (void)buffer;
    (void)end_stream;
  }
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override {
    (void)frame;
    (void)ctx;
    return absl::OkStatus();
  }
};

class SshCodecFactory : public CodecFactory {
public:
  SshCodecFactory(Api::Api& api) : api_(api) {
    ConnectionService::RegisterChannelType(
        "session", [](uint32_t channelId) { return std::make_unique<Session>(channelId); });
  }
  ServerCodecPtr createServerCodec() const override {
    return std::make_unique<SshServerCodec>(api_);
  }
  ClientCodecPtr createClientCodec() const override { return std::make_unique<SshClientCodec>(); }

private:
  Api::Api& api_;
};

DECLARE_FACTORY(SshCodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
