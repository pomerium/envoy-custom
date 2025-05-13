#pragma once

#include <numeric> // IWYU pragma: keep

// alias for std::sub_sat, which is available in clang under a different name but not technically
// part of the standard until C++26.
template <typename T>
constexpr T sub_sat(T x, T y) noexcept {
  return std::__sub_sat(x, y);
}
