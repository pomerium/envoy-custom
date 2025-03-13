#pragma once

#include <cerrno>
#include <unistd.h>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/shared.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
class SshCodecFactoryConfig : public CodecFactoryConfig {
public:
  // CodecFactoryConfig
  CodecFactoryPtr
  createCodecFactory(const Protobuf::Message& config,
                     Envoy::Server::Configuration::ServerFactoryContext& context) override;
  std::string name() const override {
    return "envoy.generic_proxy.codecs.ssh";
  }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

class SshCodecFactory : public CodecFactory {
public:
  SshCodecFactory(Api::Api& api,
                  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                  std::unique_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr,
                  CreateGrpcClientFunc create_grpc_client);
  ServerCodecPtr createServerCodec() const override;
  ClientCodecPtr createClientCodec() const override;

private:
  Api::Api& api_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr_;
  CreateGrpcClientFunc create_grpc_client_;
};

DECLARE_FACTORY(SshCodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
