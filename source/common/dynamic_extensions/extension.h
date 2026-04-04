#pragma once

#define _STR(x) #x
#define STR(x) _STR(x)
#define CAT(a, b) a##b

#define _DYNAMIC_EXTENSION_METADATA(key, value)                                                                                                  \
  namespace {                                                                                                                                    \
  __attribute__((used, retain, section(".dx_metadata"), aligned(1))) static const char CAT(dynamic_extension_info_, key)[] = STR(key) "=" value; \
  }

#define DYNAMIC_EXTENSION(value) _DYNAMIC_EXTENSION_METADATA(id, value)
#define DYNAMIC_EXTENSION_LICENSE(value) _DYNAMIC_EXTENSION_METADATA(license, value)
#define DYNAMIC_EXTENSION_EXPORT __attribute__((used, retain, visibility("default")))
