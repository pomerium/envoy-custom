#pragma once

#include <cerrno>
#include <unistd.h>

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"

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

class SshCodecFactory : public CodecFactory,
                        public SecretsProvider {
public:
  SshCodecFactory(Envoy::Server::Configuration::ServerFactoryContext& context,
                  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                  CreateGrpcClientFunc create_grpc_client,
                  StreamTrackerSharedPtr active_stream_tracker);
  ServerCodecPtr createServerCodec() const override;
  ClientCodecPtr createClientCodec() const override;

  std::vector<openssh::SSHKeySharedPtr> hostKeys() const override { return host_keys_; }
  openssh::SSHKeySharedPtr userCaKey() const override { return user_ca_key_; }

private:
  Envoy::Server::Configuration::ServerFactoryContext& context_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  CreateGrpcClientFunc create_grpc_client_;
  StreamTrackerSharedPtr stream_tracker_;

  std::vector<openssh::SSHKeySharedPtr> host_keys_;
  openssh::SSHKeySharedPtr user_ca_key_;
};

DECLARE_FACTORY(SshCodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
