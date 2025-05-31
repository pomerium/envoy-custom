#pragma once

#include <vector>
#include <span>
#include <array>

using bytes = std::vector<uint8_t>;

using bytes_view = std::span<const uint8_t>;

template <size_t N>
using fixed_bytes = std::array<uint8_t, N>;

template <size_t N>
using fixed_bytes_view = std::span<const uint8_t, N>;

// verify that size() and size_bytes() can be used interchangeably
static_assert(fixed_bytes_view<1>{{}}.size() ==
              fixed_bytes_view<1>{{}}.size_bytes());

using bytes_list = std::vector<bytes>;

using string_list = std::vector<std::string>;

// Helper function to convert a container (anything with begin() and end() methods) of uint8_t
// entries into a bytes object.
constexpr bytes to_bytes(const auto& view) {
  return {view.begin(), view.end()};
}

constexpr bytes operator""_bytes(const char* str, size_t len) {
  return to_bytes(std::string_view(str, len));
}

constexpr uint8_t operator""_byte(char c) {
  return static_cast<uint8_t>(c);
}

template <typename T>
struct is_bytes : std::false_type {};

template <>
struct is_bytes<bytes> : std::true_type {};

template <typename T>
static constexpr bool is_bytes_v = is_bytes<T>::value;

template <typename T>
struct is_fixed_bytes : std::false_type {};

template <size_t N>
struct is_fixed_bytes<fixed_bytes<N>> : std::true_type {};

template <typename T>
static constexpr bool is_fixed_bytes_v = is_fixed_bytes<T>::value;