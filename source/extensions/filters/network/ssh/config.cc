#include "source/extensions/filters/network/ssh/config.h"
#include "bazel-out/k8-dbg/bin/api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/session.h"
#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
    const Protobuf::Message& config, Envoy::Server::Configuration::ServerFactoryContext& context) {

  const auto& typed_config = dynamic_cast<const pomerium::extensions::ssh::CodecConfig&>(config);
  auto shared_config = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
  shared_config->CopyFrom(typed_config);

  auto createClient = [&context, shared_config]() {
    return context.clusterManager().grpcAsyncClientManager().getOrCreateRawAsyncClient(
        shared_config->grpc_service(), context.scope(), true);
  };

  return std::make_unique<SshCodecFactory>(context.api(), shared_config, createClient);
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Api::Api& api,
                                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                 CreateGrpcClientFunc create_grpc_client)
    : api_(api), config_(config), create_grpc_client_(create_grpc_client) {
  ConnectionService::RegisterChannelType(
      "session", [](uint32_t channelId) { return std::make_unique<Session>(channelId); });
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerCodec>(api_, config_, create_grpc_client_);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientCodec>(api_, config_);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::ssh::CodecConfig>();
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec