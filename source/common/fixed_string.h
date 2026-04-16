#pragma once

#include <algorithm>
#include <string_view>
#include <fmt/compile.h>

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

// Used with FMT_STATIC_FORMAT() to produce user-defined static_assert messages.
// Example: `static_assert(false, fixed_fmt_string{FMT_STATIC_FORMAT("error: {}", ...)})`
template <size_t N>
struct fixed_fmt_string {
  consteval fixed_fmt_string(fmt::static_format_result<N> fmt_result) {
    // for some reason, static_format_result::str() is not constexpr, so we can't use it directly
    std::copy_n(std::bit_cast<static_format_result_data>(fmt_result).data, N, static_cast<char*>(value));
  }

  // implements the static_assert constant expression requirements
  consteval size_t size() { return N - 1; }
  consteval const char* data() { return static_cast<const char*>(value); }

  char value[N];

private:
  struct static_format_result_data {
    char data[N];
  };
};