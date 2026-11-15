#pragma once

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include <bit>
#include <concepts>
#include <type_traits>

namespace wire {

template <std::unsigned_integral T>
struct selector_field : field<T, None> {
  using field<T>::field;
  using field<T>::value;
  using field<T>::operator=;

  using field_type = field<T, None>;

  template <T Bit>
    requires (std::has_single_bit(Bit))
  constexpr bool test() const {
    return (value & Bit) != 0;
  }

  template <bool B>
  constexpr bool test() const {
    return value == B;
  }
};

template <typename T>
struct is_selector_field : std::false_type {};

template <std::unsigned_integral T>
struct is_selector_field<selector_field<T>> : std::true_type {};

template <typename T>
constexpr bool is_selector_field_v = is_selector_field<T>::value;

template <typename T, std::unsigned_integral auto EnableFlag, wire::EncodingOptions Opt = None>
  requires (std::same_as<decltype(EnableFlag), bool> || std::has_single_bit(EnableFlag))
struct optional_field : field<T, Opt> {
  using field<T, Opt>::field;
  using field<T, Opt>::value;
  using field<T, Opt>::operator=;

  using field_type = field<T, Opt>;
};

template <typename T>
struct is_optional_field : std::false_type {};

template <typename T, std::unsigned_integral auto Selector, wire::EncodingOptions Opt>
struct is_optional_field<optional_field<T, Selector, Opt>> : std::true_type {};

template <typename T>
constexpr bool is_optional_field_v = is_optional_field<T>::value;

namespace internal {
template <typename>
struct optional_field_selector_bit;

template <typename T, std::unsigned_integral auto EnableFlag, wire::EncodingOptions Opt>
struct optional_field_selector_bit<optional_field<T, EnableFlag, Opt>> : std::integral_constant<decltype(EnableFlag), EnableFlag> {};
} // namespace internal

} // namespace wire