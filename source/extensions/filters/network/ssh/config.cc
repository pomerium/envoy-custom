#include "source/extensions/filters/network/ssh/config.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/shared.h"
#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
  const Protobuf::Message& config, Envoy::Server::Configuration::ServerFactoryContext& context) {
  const auto& typed_config = dynamic_cast<const pomerium::extensions::ssh::CodecConfig&>(config);
  auto conf = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
  conf->CopyFrom(typed_config);
  auto createClient = [&context, conf]() {
    auto factory = context.clusterManager().grpcAsyncClientManager().factoryForGrpcService(
      conf->grpc_service(), context.scope(), true);
    THROW_IF_NOT_OK_REF(factory.status());
    return (*factory)->createUncachedRawAsyncClient();
  };

  auto sharedSessions = std::make_shared<absl::node_hash_map<stream_id_t, std::shared_ptr<ActiveSession>>>();
  auto slotPtr = std::make_unique<ThreadLocal::TypedSlot<ThreadLocalData>>(context.threadLocal());
  slotPtr->set([sharedSessions](Dispatcher& /*dispatcher*/) -> std::unique_ptr<ThreadLocalData> {
    return std::make_unique<ThreadLocalData>(sharedSessions);
  });

  return std::make_unique<SshCodecFactory>(context.api(), conf, std::move(slotPtr), createClient);
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Api::Api& api,
                                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                 std::unique_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr,
                                 CreateGrpcClientFunc create_grpc_client)
    : api_(api),
      config_(config),
      slot_ptr_(std::move(slot_ptr)),
      create_grpc_client_(create_grpc_client) {
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerTransport>(api_, config_, create_grpc_client_, slot_ptr_);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientTransport>(api_, config_, slot_ptr_);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::ssh::CodecConfig>();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec