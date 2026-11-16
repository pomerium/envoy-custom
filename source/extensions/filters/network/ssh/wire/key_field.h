#pragma once

#include <type_traits>

namespace wire {

template <typename T>
struct key_field {
  using type = T;
};

template <typename T>
inline constexpr bool operator==(const key_field<T>&, const key_field<T>&) {
  return true;
}

template <typename T>
struct is_key_field : std::false_type {};

template <typename T>
struct is_key_field<key_field<T>> : std::true_type {};

template <typename T>
static constexpr bool is_key_field_v = is_key_field<T>::value;

} // namespace wire