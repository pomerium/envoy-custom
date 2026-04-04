#pragma once

#include <vector>
#include <span>
#include <array>

using bytes = std::vector<uint8_t>;

using bytes_view = std::span<const uint8_t, std::dynamic_extent>;

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

constexpr bytes_view to_bytes_view(std::string_view sv) {
#pragma clang unsafe_buffer_usage begin
  return {reinterpret_cast<const uint8_t*>(sv.data()), sv.size()};
#pragma clang unsafe_buffer_usage end
}

constexpr bytes operator""_bytes(const char* str, size_t len) {
  return to_bytes(std::string_view(str, len));
}

constexpr uint8_t operator""_byte(char c) {
  return static_cast<uint8_t>(c);
}

constexpr bytes_view operator""_bv(const char* str, size_t len) {
  return to_bytes_view(std::string_view(str, len));
}

constexpr bool operator==(const bytes_view& lhs, const bytes_view& rhs) {
  return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

constexpr bool operator!=(const bytes_view& lhs, const bytes_view& rhs) {
  return !std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

constexpr std::string_view to_string_view(const bytes_view& bv) {
  return {reinterpret_cast<const char*>(bv.data()), bv.size()};
}

constexpr std::string to_string(const bytes_view& bv) {
  return {bv.begin(), bv.end()};
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