#include "source/extensions/filters/network/ssh/config.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
    const Protobuf::Message&, Envoy::Server::Configuration::ServerFactoryContext& context) {
  return std::make_unique<SshCodecFactory>(context.api());
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec