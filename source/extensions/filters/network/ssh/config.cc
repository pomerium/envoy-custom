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
    return context.clusterManager().grpcAsyncClientManager().getOrCreateRawAsyncClient(
      conf->grpc_service(), context.scope(), true);
  };

  auto sharedSessions = std::make_shared<absl::node_hash_map<uint64_t, std::shared_ptr<ActiveSession>>>();
  auto slotPtr = std::make_shared<ThreadLocal::TypedSlot<SharedThreadLocalData>>(context.threadLocal());
  slotPtr->set([sharedSessions](Dispatcher& /*dispatcher*/) -> std::shared_ptr<SharedThreadLocalData> {
    return std::make_shared<SharedThreadLocalData>(sharedSessions);
  });

  return std::make_unique<SshCodecFactory>(context.api(), conf, slotPtr, createClient);
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Api::Api& api,
                                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                 std::shared_ptr<ThreadLocal::TypedSlot<SharedThreadLocalData>> slot_ptr,
                                 CreateGrpcClientFunc create_grpc_client)
    : api_(api),
      config_(config),
      slot_ptr_(slot_ptr),
      create_grpc_client_(create_grpc_client) {
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerCodec>(api_, config_, create_grpc_client_, slot_ptr_);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientCodec>(api_, config_, slot_ptr_);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::ssh::CodecConfig>();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec