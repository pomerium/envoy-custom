#pragma once

#include "envoy/server/instance.h"
#include "source/common/dynamic_extensions/metadata.h"

namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader {

using DynamicExtensionInitFunc = void (*)(const google::protobuf::Any&, Envoy::Server::Instance&);
using DynamicExtensionInitNoConfigFunc = void (*)(Envoy::Server::Instance&);

class DynamicExtensionHandle {
public:
  DynamicExtensionHandle(void* raw_handle, ExtensionInfo info, Envoy::OptRef<const google::protobuf::Any> config = {});
  ~DynamicExtensionHandle();
  absl::Status dynamicExtensionInit(Envoy::Server::Instance& instance);

  const ExtensionInfo& info() const { return info_; }

private:
  void loadAbiSymbols();

  void* raw_handle_;
  ExtensionInfo info_;
  Envoy::OptRef<const google::protobuf::Any> config_;

  DynamicExtensionInitFunc abi_dynamic_extension_init_{};
  DynamicExtensionInitNoConfigFunc abi_dynamic_extension_init_no_config_{};
};

using DynamicExtensionHandlePtr = std::unique_ptr<DynamicExtensionHandle>;

} // namespace Envoy::Extensions::Bootstrap::DynamicExtensionLoader