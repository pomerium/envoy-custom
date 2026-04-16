#pragma once

#include "envoy/registry/registry.h"
#include "source/common/fixed_string.h"
#include "fmt/compile.h"

namespace detail {
template <fixed_string Name>
struct use_factory_guard {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"
  static_assert(false, fixed_fmt_string{FMT_STATIC_FORMAT(
                         "missing required declaration: `DYNAMIC_EXTENSION_USE_FACTORY_BASE({});`",
                         Name.to_string())});
#pragma clang diagnostic pop
};
} // namespace detail

// This must be declared in global scope before registering a factory with an existing base type
// known to the host, so that the extension will use the same instance of the factory registry for
// this type instead of instantiating its own.
#define DYNAMIC_EXTENSION_USE_FACTORY_BASE(BASE)                \
  namespace detail {                                            \
  template <> struct use_factory_guard<#BASE> {};               \
  }                                                             \
  extern template class Envoy::Registry::FactoryRegistry<BASE>; \
  extern template class Envoy::Registry::FactoryRegistryProxyImpl<BASE>;

// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define _DYNAMIC_EXTENSION_REGISTER_FACTORY_2(FACTORY, BASE, ID) \
  static Envoy::Registry::RegisterFactory<FACTORY, BASE>         \
    _factory_##ID

// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define _DYNAMIC_EXTENSION_REGISTER_FACTORY(FACTORY, BASE, ID) \
  _DYNAMIC_EXTENSION_REGISTER_FACTORY_2(FACTORY, BASE, ID)

// This should be called from within dynamicExtensionInit, in place of the usual REGISTER_FACTORY.
#define DYNAMIC_EXTENSION_REGISTER_FACTORY(FACTORY, BASE) \
  (void)detail::use_factory_guard<#BASE>{};               \
  _DYNAMIC_EXTENSION_REGISTER_FACTORY(FACTORY, BASE, __COUNTER__)

#undef DECLARE_FACTORY
#define DECLARE_FACTORY(FACTORY) static_assert(false, "use DYNAMIC_EXTENSION_REGISTER_FACTORY instead");

#undef REGISTER_FACTORY
#define REGISTER_FACTORY(FACTORY, BASE) static_assert(false, "use DYNAMIC_EXTENSION_REGISTER_FACTORY instead")
