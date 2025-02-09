#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "validate/validate.h"
#include <cerrno>
#include <unistd.h>

#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
class SshCodecFactoryConfig : public CodecFactoryConfig {
public:
  // CodecFactoryConfig
  CodecFactoryPtr
  createCodecFactory(const Protobuf::Message& config,
                     Envoy::Server::Configuration::ServerFactoryContext& context) override;
  std::string name() const override { return "envoy.generic_proxy.codecs.ssh"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

class SshCodecFactory : public CodecFactory {
public:
  SshCodecFactory(Api::Api& api);
  ServerCodecPtr createServerCodec() const override;
  ClientCodecPtr createClientCodec() const override;

private:
  Api::Api& api_;
};

DECLARE_FACTORY(SshCodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
