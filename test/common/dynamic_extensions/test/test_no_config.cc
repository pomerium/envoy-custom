#include "source/common/dynamic_extensions/extension.h"
#include "envoy/server/instance.h"

DYNAMIC_EXTENSION("test.no-config");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

extern int test_no_config_dynamic_extension_init_called;

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  test_no_config_dynamic_extension_init_called = 1;
}
