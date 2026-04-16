#include "source/extensions/bootstrap/dynamic_extension_loader/handle.h"
#include "source/common/dynamic_extensions/extension.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

DynamicExtensionHandle::DynamicExtensionHandle(void* raw_handle, ExtensionInfo info, Envoy::OptRef<const google::protobuf::Any> config)
    : raw_handle_(raw_handle),
      info_(info),
      config_(config) {
  loadAbiSymbols();
}

DynamicExtensionHandle::~DynamicExtensionHandle() {
  // best-effort only, this is not guaranteed to always work.
  dlclose(raw_handle_);
}

absl::Status DynamicExtensionHandle::dynamicExtensionInit(Envoy::Server::Instance& instance) {
  if (config_.has_value()) {
    if (abi_dynamic_extension_init_ != nullptr) {
      ENVOY_LOG_MISC(debug, "calling dynamicExtensionInit for extension {} with the following configuration:\n{}",
                     info_.metadata.id, config_->DebugString());
      abi_dynamic_extension_init_(*config_, instance);
    } else if (abi_dynamic_extension_init_no_config_ != nullptr) {
      return absl::InvalidArgumentError(fmt::format(
        "extension {} does not accept configuration, but the following configuration is set for this extension ID:\n{}",
        info_.metadata.id, config_->DebugString()));
    } else {
      return absl::InvalidArgumentError(fmt::format(
        "extension {} does not define a dynamicExtensionInit entrypoint, but the following configuration is set for this extension ID:\n{}",
        info_.metadata.id, config_->DebugString()));
    }
  } else {
    if (abi_dynamic_extension_init_no_config_ != nullptr) {
      ENVOY_LOG_MISC(debug, "calling dynamicExtensionInit for extension {} (no configuration)", info_.metadata.id);
      abi_dynamic_extension_init_no_config_(instance);
    } else if (abi_dynamic_extension_init_ != nullptr) {
      return absl::InvalidArgumentError(fmt::format(
        "extension {} requires configuration, but no configuration was set for this extension ID", info_.metadata.id));
    } else {
      ENVOY_LOG_MISC(debug, "extension {} does not define a dynamicExtensionInit entrypoint");
    }
  }
  return absl::OkStatus();
}

void DynamicExtensionHandle::loadAbiSymbols() {
  if (auto* sp = dlsym(raw_handle_, dynamic_extension_init_sym); sp != nullptr) {
    abi_dynamic_extension_init_ = reinterpret_cast<DynamicExtensionInitFunc>(sp);
  }
  if (auto* sp = dlsym(raw_handle_, dynamic_extension_init_no_config_sym); sp != nullptr) {
    abi_dynamic_extension_init_no_config_ = reinterpret_cast<DynamicExtensionInitNoConfigFunc>(sp);
  }
}

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader