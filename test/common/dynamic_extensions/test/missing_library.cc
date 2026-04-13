#include "test/common/dynamic_extensions/test/missing_library.h"

int symbolNotAvailableInExtensionHost() {
  return 42;
}