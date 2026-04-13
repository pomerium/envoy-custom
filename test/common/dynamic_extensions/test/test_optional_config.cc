#include "source/common/dynamic_extensions/extension.h"
#include "envoy/server/instance.h"

DYNAMIC_EXTENSION("test.optional-config");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

extern int test_optional_config_dynamic_extension_init_called;

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  test_optional_config_dynamic_extension_init_called = 1;
}

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(const google::protobuf::Any& config, Envoy::Server::Instance& server) {
  ENVOY_LOG_MISC(info, config.DebugString());
  test_optional_config_dynamic_extension_init_called = 2;
}