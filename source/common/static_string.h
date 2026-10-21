#pragma once

#include <algorithm>
#include <string_view>

#include "fmt/compile.h"

namespace detail {
template <size_t N>
struct static_format_result_data {
  char data[N];
};
} // namespace detail

// A simple compile-time-only string.
// The string is stored null-terminated to allow conversions to both string_view and const char*,
// but N does not include the null-terminator.
// Note that builtin array types deduced from string literals include the null-terminator in the
// size, so a custom deduction guide is used to subtract 1 from the usual length in that case.
template <size_t N>
struct static_string {
  using char_type = char;
  char_type value[N + 1]{};

  consteval static_string(const char_type (&str)[N + 1]) {
    std::copy_n(static_cast<const char_type*>(str), N, static_cast<char_type*>(value));
  }
  consteval explicit static_string(char_type* str) {
    std::copy_n(const_cast<const char_type*>(str), N, static_cast<char_type*>(value));
  }
  consteval explicit static_string(std::string_view view) {
    if (view.size() != N) {
      // static_assert can't be used with function arguments since they are never constexpr, even
      // within a consteval function, so this is the best we can do
      throw "string_view size is not equal to N";
    }
    view.copy(static_cast<char_type*>(value), N);
  }

  // Conversion from fmt::static_format_result which is returned by FMT_STATIC_FORMAT().
  // Note: fmt::static_format_result<N> includes the null-terminator.
  consteval explicit static_string(fmt::static_format_result<N + 1> fmt_result)
      // for some reason, static_format_result::str() is not constexpr, so we can't use it directly
      : static_string(static_cast<char*>(std::bit_cast<detail::static_format_result_data<N + 1>>(fmt_result).data)) {}

  constexpr operator std::string_view() const {
    return {static_cast<const char_type*>(value), N};
  }

  // Required by static_assert user-defined message types
  constexpr size_t size() const { return N; }
  constexpr const char_type* data() const { return static_cast<const char_type*>(value); }

  // Required by FMT_STATIC_FORMAT. Note this must not be explicit.
  constexpr operator fmt::basic_string_view<char_type>() const {
    return {static_cast<const char_type*>(value), N};
  }
  constexpr char_type operator[](int i) const { return value[i]; }
};

// Deduction guide for string literals. The type 'char[N+1]' can't be deduced automatically, so
// this will construct a fixed_string of N-1 chars from a string literal, where N here is the same
// as N+1 in the constructor.
template <size_t N>
  requires (N > 0)
static_string(const char (&str)[N]) -> static_string<N - 1>;

// Deduction guide for fmt::static_format_result<N>
template <size_t N>
  requires (N > 0)
static_string(fmt::static_format_result<N>) -> static_string<N - 1>;

template <size_t A, size_t B>
consteval auto operator<=>(const static_string<A>& lhs, const static_string<B>& rhs) {
  return static_cast<std::string_view>(lhs) <=> static_cast<std::string_view>(rhs);
};

template <size_t A, size_t B>
consteval bool operator==(const static_string<A>& lhs, const static_string<B>& rhs) {
  return static_cast<std::string_view>(lhs) == static_cast<std::string_view>(rhs);
};

template <size_t A>
constexpr bool operator==(const static_string<A>& lhs, const char* rhs) {
  return static_cast<std::string_view>(lhs) == std::string_view{rhs};
};

template <size_t A>
constexpr bool operator==(const static_string<A>& lhs, std::string_view rhs) {
  return static_cast<std::string_view>(lhs) == rhs;
};

// fmt::format support
template <size_t N>
struct fmt::formatter<static_string<N>> : fmt::formatter<fmt::string_view> {
  constexpr auto format(const static_string<N>& str, format_context& ctx) const {
    return fmt::formatter<fmt::string_view>::format(str, ctx);
  }
};

template <size_t N>
inline std::ostream& operator<<(std::ostream& os, const static_string<N>& str) {
  return os << static_cast<std::string_view>(str);
}
