#pragma once

#include "source/common/static_string.h"

template <static_string Err>
struct static_error {
  static constexpr static_string error = Err;
  static constexpr std::string_view message() { return error; }
  static constexpr bool ok() { return false; }

  // Required by static_assert user-defined message types
  consteval size_t size() const { return error.size(); }
  consteval const char* data() const { return error.data(); }

  // Required by FMT_STATIC_FORMAT. Note this must not be explicit.
  consteval operator fmt::basic_string_view<char>() const { return error; }
  consteval char operator[](int i) const { return error[i]; }
};

struct no_error_t {
  static constexpr bool ok() {
    return true;
  }
  static constexpr std::string_view message() {
    return "";
  }
};
static constexpr no_error_t no_error{};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"

template <static_string Fmt, auto... Args>
consteval auto static_errorf() {
  return static_error<static_string{FMT_STATIC_FORMAT(Fmt, Args...)}>{};
}
#pragma clang diagnostic pop

// Returns the first error in the list where ok() == false. If all errors return ok() == true,
// returns the last error.
template <auto First, auto... Rest>
consteval decltype(auto) first_error() {
  if constexpr (sizeof...(Rest) == 0) {
    return First;
  } else {
    if constexpr (!First.ok()) {
      return First;
    } else {
      return first_error<Rest...>();
    }
  }
}
