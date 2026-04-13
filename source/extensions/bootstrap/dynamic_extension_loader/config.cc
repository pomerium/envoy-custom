#include "source/extensions/bootstrap/dynamic_extension_loader/config.h"
#include "source/extensions/bootstrap/dynamic_extension_loader/loader.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

Server::BootstrapExtensionPtr
DynamicExtensionLoaderFactory::createBootstrapExtension(const Protobuf::Message& config,
                                                        Server::Configuration::ServerFactoryContext& context) {
  const auto& typedConfig = MessageUtil::downcastAndValidate<const pomerium::extensions::dynamic_extension_loader::Config&>(
    config, context.messageValidationVisitor());
  return std::make_unique<ExtensionLoader>(typedConfig, context);
}

REGISTER_FACTORY(DynamicExtensionLoaderFactory, Server::Configuration::BootstrapExtensionFactory);

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader