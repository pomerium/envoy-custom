#pragma once
#include "source/common/dynamic_extensions/version_hash.h"

#define _POMERIUM_VERSION_SYMBOL_NAME_CAT(a, b) a##b

#define _POMERIUM_VERSION_SYMBOL_NAME(version) \
  _POMERIUM_VERSION_SYMBOL_NAME_CAT(pomerium_envoy_version_, version)

#define POMERIUM_VERSION_SYMBOL_NAME \
  _POMERIUM_VERSION_SYMBOL_NAME(POMERIUM_BUILD_HASH)

extern "C" __attribute__((visibility("default"), used, retain)) int POMERIUM_VERSION_SYMBOL_NAME(void);
