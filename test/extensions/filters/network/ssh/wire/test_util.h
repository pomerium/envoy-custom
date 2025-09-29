#pragma once

#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "gtest/gtest.h" // IWYU pragma: keep

#include "absl/random/random.h"

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
  static auto operator()() {
    if constexpr (std::is_enum_v<T>) {
      return static_cast<T>(absl::Uniform<std::underlying_type_t<T>>(rng));
    } else {
      return absl::Uniform<T>(rng);
    }
  }
};

template <>
struct random_value_impl<bool> {
  static auto operator()() {
    return absl::Uniform(rng, 0, 2) == 1;
  }
};

template <>
struct random_value_impl<std::string> {
  static auto operator()() {
    std::string s;
    s.resize(absl::Uniform(rng, 1, 32));
    for (size_t i = 0; i < s.size(); i++) {
      do {
        s[i] = absl::Uniform(rng, ' ', '~');
      } while (s[i] == ',');
    }
    return s;
  }
};

template <>
struct random_value_impl<bytes> {
  static auto operator()() {
    bytes b;
    b.resize(absl::Uniform(rng, 0, 32));
    for (size_t i = 0; i < b.size(); i++) {
      b[i] = absl::Uniform<uint8_t>(rng);
    }
    return b;
  }
};

template <size_t N>
struct random_value_impl<fixed_bytes<N>> {
  static auto operator()() {
    fixed_bytes<N> b;
    for (size_t i = 0; i < N; i++) {
      b[i] = absl::Uniform<uint8_t>(rng);
    }
    return b;
  }
};

template <typename T>
  requires (!std::same_as<T, uint8_t>)
struct random_value_impl<std::vector<T>> {
  static auto operator()() {
    std::vector<T> v;
    v.resize(absl::Uniform(rng, 1, 10));
    for (size_t i = 0; i < v.size(); i++) {
      v[i] = random_value_impl<T>{}();
    }
    return v;
  }
};

} // namespace detail

template <typename T>
inline constexpr detail::random_value_impl<T> random_value{};

} // namespace wire::test

namespace wire {
// required for gtest formatting
std::ostream& operator<<(std::ostream& os, const SshMessageType& t) {
  return os << fmt::to_string(t);
}
} // namespace wire