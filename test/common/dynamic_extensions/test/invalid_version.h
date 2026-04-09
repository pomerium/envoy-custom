
#include "source/common/dynamic_extensions/version.h"

// The special version mismatch error message is used when a missing symbol matches the format of
// the pomerium version symbol. We can just define another one with a bogus version suffix to
// trigger the error.
extern "C" __attribute__((visibility("default"), used, retain)) int _POMERIUM_VERSION_SYMBOL_NAME(0000000000000000000000000000000000000000)(void);
