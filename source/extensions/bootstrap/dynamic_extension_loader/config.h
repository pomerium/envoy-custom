#pragma once

#include "api/extensions/bootstrap/dynamic_extension_loader/dynamic_extension_loader.pb.h"
#include "api/extensions/bootstrap/dynamic_extension_loader/dynamic_extension_loader.pb.validate.h"
#include "envoy/server/bootstrap_extension_config.h"
#include "source/common/protobuf/protobuf.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

class DynamicExtensionLoaderFactory : public Server::Configuration::BootstrapExtensionFactory {
public:
  ~DynamicExtensionLoaderFactory() override = default;
  std::string name() const override { return "envoy.bootstrap.dynamic_extension_loader"; }
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<pomerium::extensions::dynamic_extension_loader::Config>();
  }
};

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader