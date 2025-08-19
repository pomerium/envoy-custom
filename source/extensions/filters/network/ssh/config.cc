#include "source/extensions/filters/network/ssh/config.h"

#include "source/extensions/filters/network/ssh/client_transport.h"   // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/server_transport.h"   // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/tunnel_cluster.h"     // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
  const Protobuf::Message& config, Envoy::Server::Configuration::ServerFactoryContext& context) {
  const auto& typed_config = dynamic_cast<const pomerium::extensions::ssh::CodecConfig&>(config);
  MessageUtil::validate(typed_config, context.messageValidationVisitor());
  auto conf = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
  conf->CopyFrom(typed_config);
  auto createClient = [&context, conf]() {
    auto factory = context.clusterManager().grpcAsyncClientManager().factoryForGrpcService(
      conf->grpc_service(), context.scope(), true);
    THROW_IF_NOT_OK_REF(factory.status());
    return (*factory)->createUncachedRawAsyncClient();
  };

  return std::make_unique<SshCodecFactory>(context, conf, createClient,
                                           ActiveStreamTracker::fromContext(context, typed_config.active_stream_tracker()));
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Envoy::Server::Configuration::ServerFactoryContext& context,
                                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                 CreateGrpcClientFunc create_grpc_client,
                                 std::shared_ptr<ActiveStreamTracker> active_stream_tracker)
    : context_(context),
      config_(config),
      create_grpc_client_(create_grpc_client),
      active_stream_tracker_(std::move(active_stream_tracker)) {
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerTransport>(context_, config_, create_grpc_client_,
                                              active_stream_tracker_);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientTransport>(context_, config_);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::ssh::CodecConfig>();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec