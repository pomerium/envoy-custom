#include "source/common/dynamic_extensions/extension.h"
#include "test/common/dynamic_extensions/test/invalid_version.h"

DYNAMIC_EXTENSION("test.version-mismatch");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

namespace {
__attribute__((used, retain)) int _ = _POMERIUM_VERSION_SYMBOL_NAME(0000000000000000000000000000000000000000)();
}