#pragma once
#include "source/common/dynamic_extensions/version_hash.h"

#define _POMERIUM_VERSION_STR_2(a) #a
#define _POMERIUM_VERSION_STR(a) _POMERIUM_VERSION_STR_2(a)
#define _POMERIUM_VERSION_CAT(a, b) a##b

#define _POMERIUM_VERSION_SYMBOL_NAME(version) \
  _POMERIUM_VERSION_CAT(pomerium_envoy_version_, version)

#define POMERIUM_VERSION_SYMBOL_NAME \
  _POMERIUM_VERSION_SYMBOL_NAME(POMERIUM_ENVOY_VERSION)

extern "C" __attribute__((visibility("default"), used, retain)) int POMERIUM_VERSION_SYMBOL_NAME(void);

constexpr const char pomerium_envoy_version_str[] = _POMERIUM_VERSION_STR(POMERIUM_ENVOY_VERSION);