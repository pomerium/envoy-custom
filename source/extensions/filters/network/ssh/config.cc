#include "source/extensions/filters/network/ssh/config.h"
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/session.h"
#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
    const Protobuf::Message&, Envoy::Server::Configuration::ServerFactoryContext& context) {
  return std::make_unique<SshCodecFactory>(context.api());
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Api::Api& api) : api_(api) {
  ConnectionService::RegisterChannelType(
      "session", [](uint32_t channelId) { return std::make_unique<Session>(channelId); });
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerCodec>(api_);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientCodec>(api_);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::SshCodecConfig>();
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec