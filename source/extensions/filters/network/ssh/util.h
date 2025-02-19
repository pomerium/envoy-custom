#pragma once

#include <vector>
#include <string>
#include <span>

#include "absl/status/statusor.h" // IWYU pragma: keep
#include "fmt/std.h"              // IWYU pragma: keep

using bytes = std::vector<uint8_t>;

template <size_t N = std::dynamic_extent>
using bytes_view = std::span<const uint8_t, N>;

template <size_t N>
using fixed_bytes = std::array<uint8_t, N>;

template <size_t N>
using fixed_bytes_view = std::span<const uint8_t, N>;

using name_list = std::vector<std::string>;

inline bytes to_bytes(const auto& view) {
  return bytes{view.begin(), view.end()};
}