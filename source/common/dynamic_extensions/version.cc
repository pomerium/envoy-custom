#include "source/common/dynamic_extensions/version.h"

__asm__(".symver pomerium_envoy_version,pomerium_envoy_version@" POMERIUM_BUILD_HASH ",remove");

extern "C" __attribute__((used, retain)) int pomerium_envoy_version = 0;