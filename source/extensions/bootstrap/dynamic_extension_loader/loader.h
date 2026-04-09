#pragma once

#include "api/extensions/bootstrap/dynamic_extension_loader/dynamic_extension_loader.pb.h"
#include "envoy/server/bootstrap_extension_config.h"
#include "source/extensions/bootstrap/dynamic_extension_loader/handle.h"
#include "source/common/dynamic_extensions/metadata.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

class ExtensionLoader : public Server::BootstrapExtension,
                        public Envoy::Logger::Loggable<Logger::Id::main> {
public:
  ExtensionLoader(const pomerium::extensions::dynamic_extension_loader::Config& config,
                  Server::Configuration::ServerFactoryContext& server_factory_context);

  void onServerInitialized(Envoy::Server::Instance& server) override;
  void onWorkerThreadInitialized() override {}

private:
  class AdminApi : public Logger::Loggable<Logger::Id::filter> {
  public:
    AdminApi(ExtensionLoader& parent, Envoy::OptRef<Server::Admin> admin);
    Http::Code handleListExtensionsEndpoint(Http::ResponseHeaderMap& response_headers,
                                            Buffer::Instance& response,
                                            Server::AdminStream& stream);

  private:
    ExtensionLoader& parent_;
  };

  struct ExtensionError {
    ExtensionInfo info;
    std::string kind;
    absl::Status err;
  };

  std::vector<ExtensionInfo> initExtensions();
  absl::StatusOr<DynamicExtensionHandlePtr> loadExtension(const ExtensionInfo& info);

  pomerium::extensions::dynamic_extension_loader::Config config_;
  Server::Configuration::ServerFactoryContext& server_factory_context_;
  std::vector<DynamicExtensionHandlePtr> handles_;
  std::vector<ExtensionError> load_errors_;
  std::unique_ptr<AdminApi> admin_api_;
};

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader