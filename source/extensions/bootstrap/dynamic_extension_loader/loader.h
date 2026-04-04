#pragma once

#include "api/extensions/bootstrap/dynamic_extension_loader/dynamic_extension_loader.pb.h"
#include "source/common/dynamic_extensions/handle.h"
#include "envoy/server/bootstrap_extension_config.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

using namespace std::literals;

class ExtensionLoader : public Server::BootstrapExtension,
                        public Envoy::Logger::Loggable<Logger::Id::config> {
public:
  ExtensionLoader(const pomerium::extensions::dynamic_extension_loader::Config& config,
                  Server::Configuration::ServerFactoryContext& server_factory_context);

  void onServerInitialized(Envoy::Server::Instance& server) override;
  void onWorkerThreadInitialized() override {}

private:
  std::vector<ExtensionInfo> initExtensions();
  absl::StatusOr<DynamicExtensionHandlePtr> loadExtension(const ExtensionInfo& info);

  pomerium::extensions::dynamic_extension_loader::Config config_;
  Server::Configuration::ServerFactoryContext& server_factory_context_;
  std::vector<DynamicExtensionHandlePtr> handles_;
};

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader