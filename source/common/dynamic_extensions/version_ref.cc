#include "source/common/dynamic_extensions/version.h"

namespace {
__attribute__((used, retain)) int _ = POMERIUM_VERSION_SYMBOL_NAME();
}