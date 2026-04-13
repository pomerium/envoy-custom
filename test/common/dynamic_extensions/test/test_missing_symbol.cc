#include "source/common/dynamic_extensions/extension.h"
#include "envoy/server/instance.h"

#include "test/common/dynamic_extensions/test/missing_library.h"

DYNAMIC_EXTENSION("test.missing-symbol");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  ENVOY_LOG_MISC(info, symbolNotAvailableInExtensionHost());
}
