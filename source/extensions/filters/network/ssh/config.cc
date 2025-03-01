#include "source/extensions/filters/network/ssh/config.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
    const Protobuf::Message& config, Envoy::Server::Configuration::ServerFactoryContext& context) {
  const auto& typed_config = dynamic_cast<const pomerium::extensions::ssh::CodecConfig&>(config);
  auto shared_config = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
  shared_config->CopyFrom(typed_config);

  auto access_log_srv = context.accessLogManager().createAccessLog(
      Filesystem::FilePathAndType(Filesystem::DestinationType::File, "/tmp/recording.server.bin"));
  THROW_IF_NOT_OK_REF(access_log_srv.status());
  auto access_log_client = context.accessLogManager().createAccessLog(
      Filesystem::FilePathAndType(Filesystem::DestinationType::File, "/tmp/recording.client.bin"));
  THROW_IF_NOT_OK_REF(access_log_srv.status());

  auto createClient = [&context, shared_config]() {
    return context.clusterManager().grpcAsyncClientManager().getOrCreateRawAsyncClient(
        shared_config->grpc_service(), context.scope(), true);
  };

  return std::make_unique<SshCodecFactory>(context.api(), shared_config, createClient, *access_log_srv, *access_log_client);
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Api::Api& api,
                                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                 CreateGrpcClientFunc create_grpc_client,
                                 AccessLog::AccessLogFileSharedPtr access_log_server,
                                 AccessLog::AccessLogFileSharedPtr access_log_client)
    : api_(api),
      config_(config),
      create_grpc_client_(create_grpc_client),
      access_log_server_(access_log_server),
      access_log_client_(access_log_client) {
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerCodec>(api_, config_, access_log_server_, create_grpc_client_);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientCodec>(api_, config_, access_log_client_);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::ssh::CodecConfig>();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec