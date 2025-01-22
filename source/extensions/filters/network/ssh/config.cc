#include "source/extensions/filters/network/ssh/config.h"

// namespace Envoy::Extensions::NetworkFilters::Ssh {
// Network::FilterFactoryCb SshFilterConfigFactory::createFilterFactoryFromProtoTyped(
//     const pomerium::extensions::SshConfig& proto_config, Server::Configuration::FactoryContext&)
//     {
//   return [proto_config](Network::FilterManager& filter_manager) -> void {
//     Network::FilterSharedPtr filter = std::make_shared<SshFilter>(proto_config);
//     filter_manager.addFilter(filter);
//   };
// }

// REGISTER_FACTORY(SshFilterConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

// } // namespace Envoy::Extensions::NetworkFilters::Ssh

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
    const Protobuf::Message&, Envoy::Server::Configuration::ServerFactoryContext& context) {
  return std::make_unique<SshCodecFactory>(context.api());
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec