#pragma once

#include "envoy/server/instance.h"
#include "source/common/dynamic_extensions/metadata.h"

using DynamicExtensionInitFunc = void (*)(Envoy::Server::Instance&);

class DynamicExtensionHandle {
public:
  DynamicExtensionHandle(void* raw_handle, ExtensionInfo info)
      : raw_handle_(raw_handle),
        info_(info) {
    loadAbiFunctions();
  }

  void dynamicExtensionInit(Envoy::Server::Instance& instance) {
    if (abi_dynamic_extension_init_ != nullptr) {
      abi_dynamic_extension_init_(instance);
    }
  }

private:
  void loadAbiFunctions() {
    abi_dynamic_extension_init_ = reinterpret_cast<DynamicExtensionInitFunc>(
      dlsym(raw_handle_, "_Z20dynamicExtensionInitRN5Envoy6Server8InstanceE"));
    if (abi_dynamic_extension_init_ == nullptr) {
      ENVOY_LOG_MISC(warn, "extension has no dynamicExtensionInit: " + info_.path);
    }
  }
  void* raw_handle_;
  ExtensionInfo info_;

  DynamicExtensionInitFunc abi_dynamic_extension_init_{};
};

using DynamicExtensionHandlePtr = std::unique_ptr<DynamicExtensionHandle>;