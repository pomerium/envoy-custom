#pragma once

#include <algorithm>
#include <string_view>

// A simple compile-time-only string.
template <size_t N>
struct fixed_string {
  consteval fixed_string(const char (&str)[N]) {
    std::copy_n(static_cast<const char*>(str), N, static_cast<char*>(value));
  }
  consteval std::string_view to_string() const {
    return static_cast<const char*>(value);
  }
  char value[N];
};

template <size_t A, size_t B>
consteval auto operator<=>(const fixed_string<A>& lhs, const fixed_string<B>& rhs) {
  return lhs.to_string() <=> rhs.to_string();
};

template <size_t A, size_t B>
consteval bool operator==(const fixed_string<A>& lhs, const fixed_string<B>& rhs) {
  return lhs.to_string() == rhs.to_string();
};