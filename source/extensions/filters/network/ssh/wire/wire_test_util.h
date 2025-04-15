#pragma once

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "gtest/gtest.h" // IWYU pragma: keep

#pragma clang unsafe_buffer_usage begin
#include "absl/random/random.h"
#pragma clang unsafe_buffer_usage end

namespace wire::test {

using BasicFieldTypes = ::testing::Types<
  uint8_t,
  uint32_t,
  uint64_t,
  SshMessageType,
  bool,
  std::string,
  bytes,
  fixed_bytes<1>,
  fixed_bytes<8>,
  fixed_bytes<16>>;

namespace detail {
static absl::BitGen rng;

template <typename T>
struct random_value_impl;

template <SshIntegerType T>
struct random_value_impl<T> {
  static T operator()() {
    if constexpr (std::is_enum_v<T>) {
      return static_cast<T>(absl::Uniform<std::underlying_type_t<T>>(rng));
    } else {
      return absl::Uniform<T>(rng);
    }
  }
};

template <>
struct random_value_impl<bool> {
  static bool operator()() {
    return absl::Uniform(rng, 0, 1) == 1;
  }
};

template <>
struct random_value_impl<std::string> {
  static std::string operator()() {
    std::string s;
    s.resize(absl::Uniform(rng, 1, 100));
    for (size_t i = 0; i < s.size(); i++) {
      s[i] = absl::Uniform(rng, ' ', '~');
    }
    return s;
  }
};

template <>
struct random_value_impl<bytes> {
  static bytes operator()() {
    bytes b;
    b.resize(absl::Uniform(rng, 1, 100));
    for (size_t i = 0; i < b.size(); i++) {
      b[i] = absl::Uniform<uint8_t>(rng);
    }
    return b;
  }
};

template <size_t N>
struct random_value_impl<fixed_bytes<N>> {
  static fixed_bytes<N> operator()() {
    fixed_bytes<N> b;
    for (size_t i = 0; i < N; i++) {
      b[i] = absl::Uniform<uint8_t>(rng);
    }
    return b;
  }
};
} // namespace detail

template <typename T>
inline constexpr detail::random_value_impl<T> random_value{};

} // namespace wire::test