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
  consteval friend auto operator<=>(const fixed_string&, const fixed_string&) = default;

  char value[N];
};