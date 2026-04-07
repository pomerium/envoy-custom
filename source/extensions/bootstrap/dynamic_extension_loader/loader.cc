#include "source/extensions/bootstrap/dynamic_extension_loader/loader.h"

#include <dlfcn.h>

#include "source/common/status.h"
#include "source/common/types.h"
#include "source/common/dynamic_extensions/metadata.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

ExtensionLoader::ExtensionLoader(const pomerium::extensions::dynamic_extension_loader::Config& config,
                                 Server::Configuration::ServerFactoryContext& server_factory_context)
    : config_(config),
      server_factory_context_(server_factory_context) {
  auto extensionInfos = initExtensions();
  for (const auto& info : extensionInfos) {
    auto handle = loadExtension(info);
    if (!handle.ok()) {
      ENVOY_LOG(error, "error loading extension {}: {}", info.path, statusToString(handle.status()));
      continue;
    }
    handles_.push_back(std::move(handle).value());
  }
}

void ExtensionLoader::onServerInitialized(Envoy::Server::Instance& server) {
  for (auto& handle : handles_) {
    handle->dynamicExtensionInit(server);
  }
}

std::vector<ExtensionInfo> ExtensionLoader::initExtensions() {
  auto paths = config_.paths();

  std::vector<ExtensionInfo> res;
  for (const auto& path : paths) {
    ExtensionInfo info{
      .path = path,
    };

    auto file = server_factory_context_.api().fileSystem().fileReadToEnd(path);
    if (!file.ok()) {
      ENVOY_LOG_MISC(error, "error reading extension {}: {}", path, file.status());
      continue;
    }

    auto metadata = readExtensionMetadata(to_bytes_view(*file));
    if (!metadata.ok()) {
      ENVOY_LOG_MISC(error, "error loading extension {}: {}", path, metadata.status());
      continue;
    }
    info.metadata = *metadata;

    res.push_back(std::move(info));
  }

  return res;
}

absl::StatusOr<DynamicExtensionHandlePtr> ExtensionLoader::loadExtension(const ExtensionInfo& info) {
  auto* rawHandle = dlopen(info.path.c_str(), RTLD_LOCAL | RTLD_LAZY);
  if (rawHandle == nullptr) {
    return absl::InvalidArgumentError(fmt::format("dlopen failed: {}", dlerror()));
  }
  rawHandle = dlopen(info.path.c_str(), RTLD_LOCAL | RTLD_NOW | RTLD_NOLOAD);
  if (rawHandle == nullptr) {
    return absl::InvalidArgumentError(fmt::format("symbol resolution failed: {}", dlerror()));
  }

  return std::make_unique<DynamicExtensionHandle>(rawHandle, info);
}

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader