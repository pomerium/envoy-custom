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

using bytes_list = std::vector<bytes>;

template <typename T>
static constexpr bool is_bytes_v = std::is_same_v<T, bytes>;

constexpr bytes to_bytes(const auto& view) {
  return {view.begin(), view.end()};
}
