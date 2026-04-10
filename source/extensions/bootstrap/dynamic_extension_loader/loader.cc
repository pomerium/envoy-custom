#include "source/extensions/bootstrap/dynamic_extension_loader/loader.h"

#include <dlfcn.h>

#include "source/common/json/json_streamer.h"
#include "source/common/status.h"
#include "source/common/types.h"
#include "source/common/dynamic_extensions/version.h"
#include "source/common/dynamic_extensions/metadata.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

using namespace std::literals;

ExtensionLoader::ExtensionLoader(const pomerium::extensions::dynamic_extension_loader::Config& config,
                                 Server::Configuration::ServerFactoryContext& server_factory_context)
    : config_(config),
      server_factory_context_(server_factory_context) {
  auto extensionInfos = initExtensions();
  for (const auto& info : extensionInfos) {
    auto handle = loadExtension(info);
    if (!handle.ok()) {
      load_errors_.push_back(ExtensionError{
        .info = info,
        .kind = "load_failure",
        .err = handle.status(),
      });
      ENVOY_LOG(error, "error loading extension {}: {}", info.path, handle.status().message());
      continue;
    }
    ENVOY_LOG(info, "loaded extension {} [id: {}; license: {}]", info.path, info.metadata.id, info.metadata.license);
    handles_.push_back(std::move(handle).value());
  }
}

void ExtensionLoader::onServerInitialized(Envoy::Server::Instance& server) {
  for (auto& handle : handles_) {
    auto stat = handle->dynamicExtensionInit(server);
    if (!stat.ok()) {
      ENVOY_LOG(error, "extension {} failed to initialize: {}", handle->info().metadata.id, statusToString(stat));
      load_errors_.push_back(ExtensionError{
        .info = handle->info(),
        .kind = "initialization_failure",
        .err = stat,
      });
      handle.reset();
    }
  }
  std::erase_if(handles_, [](auto& entry) { return entry == nullptr; });
  admin_api_ = std::make_unique<AdminApi>(*this, server.admin());
}

std::vector<ExtensionInfo> ExtensionLoader::initExtensions() {
  auto paths = config_.paths();

  std::unordered_set<std::string> pathsSeen;
  std::unordered_map<std::string, std::string> idsSeen;

  std::vector<ExtensionInfo> res;
  for (const auto& path : paths) {
    if (pathsSeen.contains(path)) {
      ENVOY_LOG(error, "duplicate extension path configured: {}", path);
      continue;
    }
    pathsSeen.insert(path);

    ExtensionInfo info{
      .path = path,
    };

    auto file = server_factory_context_.api().fileSystem().fileReadToEnd(path);
    if (!file.ok()) {
      ENVOY_LOG(error, "error reading extension {}: {}", path, file.status());
      continue;
    }

    auto metadata = readExtensionMetadata(to_bytes_view(*file));
    if (!metadata.ok()) {
      ENVOY_LOG(error, "error loading extension {}: {}", path, metadata.status());
      continue;
    }
    if (auto stat = validateExtensionMetadata(*metadata); !stat.ok()) {
      ENVOY_LOG(error, "error loading extension {}: metadata validation failed: {}", path, stat);
      continue;
    }
    info.metadata = *metadata;

    if (idsSeen.contains(info.metadata.id)) {
      ENVOY_LOG(error, "not loading extension {}: duplicate extension ID '{}' (previously loaded by {})",
                path, info.metadata.id, idsSeen.at(info.metadata.id));
      continue;
    }
    idsSeen[info.metadata.id] = path;

    res.push_back(std::move(info));
  }

  return res;
}

absl::StatusOr<DynamicExtensionHandlePtr> ExtensionLoader::loadExtension(const ExtensionInfo& info) {
  auto* rawHandle = dlopen(info.path.c_str(), RTLD_LOCAL | RTLD_NOW);
  if (rawHandle == nullptr) {
    std::string err{dlerror()};
    // Remove the "filename: " prefix, since it will be duplicated in the resulting error log
    if (auto prefix = fmt::format("{}: ", info.path); err.starts_with(prefix)) {
      err = err.substr(prefix.size());
    }

    // As a special case, make the error nicer when the pomerium_envoy_version symbol doesn't match.
    // This will be the prefix after the above prefix is removed
    if (auto prefix = "undefined symbol: pomerium_envoy_version_"sv; err.starts_with(prefix)) {
      auto version = err.substr(prefix.size());
      return absl::InvalidArgumentError(fmt::format(
        "extension was built for version {}, but the current version is {}",
        version, pomerium_envoy_version_str));
    }
    return absl::InvalidArgumentError(err);
  }

  if (config_.extension_configs().contains(info.metadata.id)) {
    return std::make_unique<DynamicExtensionHandle>(rawHandle, info, config_.extension_configs().at(info.metadata.id));
  } else {
    return std::make_unique<DynamicExtensionHandle>(rawHandle, info);
  }
}

ExtensionLoader::AdminApi::AdminApi(ExtensionLoader& parent, Envoy::OptRef<Server::Admin> admin)
    : parent_(parent) {
  if (admin.has_value()) {
    admin->addHandler(
      "/dynamic_extensions/status",
      "Status of dynamically loaded extensions",
      MAKE_ADMIN_HANDLER(handleListExtensionsEndpoint),
      false,
      false);
  }
}

Http::Code ExtensionLoader::AdminApi::handleListExtensionsEndpoint(Http::ResponseHeaderMap& response_headers,
                                                                   Buffer::Instance& response,
                                                                   Server::AdminStream& stream) {

  if (stream.getRequestHeaders().getMethodValue() != "GET") {
    return Http::Code::MethodNotAllowed;
  }

  response_headers.setReferenceContentType("application/json");
  Json::BufferStreamer w(response);
  auto root = w.makeRootMap();

  auto renderInfo = [](Json::BufferStreamer::Map& obj, const ExtensionInfo& info) {
    obj.addKey("path");
    obj.addString(info.path);
    obj.addKey("id");
    obj.addString(info.metadata.id);
    obj.addKey("license");
    obj.addString(info.metadata.license);
    if (!info.metadata.unknown_keys.empty()) {
      obj.addKey("unknown_keys");
      auto unknownKeys = obj.addMap();
      for (const auto& [k, v] : info.metadata.unknown_keys) {
        unknownKeys->addKey(k);
        unknownKeys->addString(v);
      }
    }
  };
  {
    root->addKey("loaded");
    auto loadedExtensions = root->addArray();
    for (const auto& handle : parent_.handles_) {
      auto obj = loadedExtensions->addMap();
      const auto& info = handle->info();
      renderInfo(*obj, info);
    }
  }

  {
    root->addKey("failed");
    auto failed = root->addArray();
    for (const auto& error : parent_.load_errors_) {
      auto obj = failed->addMap();
      {
        obj->addKey("info");
        auto infoObj = obj->addMap();
        renderInfo(*infoObj, error.info);
      }
      {
        obj->addKey("kind");
        obj->addString(error.kind);
      }
      obj->addKey("error");
      obj->addString(error.err.message());
    }
  }

  return Http::Code::OK;
};

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader