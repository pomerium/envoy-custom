#pragma once

#include <concepts>

// https://en.cppreference.com/w/cpp/numeric/sub_sat
// std::sub_sat is only available in C++26
template <std::unsigned_integral T>
constexpr T sub_sat(T x, T y) noexcept {
  if (T result; !__builtin_sub_overflow(x, y, &result)) {
    return result;
  }
  return 0;
}

template <std::unsigned_integral T>
constexpr bool sub_overflow(T* x, T delta) noexcept {
  return __builtin_sub_overflow(*x, delta, x);
}

template <std::unsigned_integral T>
constexpr bool add_overflow(T* x, T delta) noexcept {
  return __builtin_add_overflow(*x, delta, x);
}