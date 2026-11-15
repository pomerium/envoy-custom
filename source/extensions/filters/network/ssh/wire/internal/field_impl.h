#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/buffer_io.h"
#include "source/extensions/filters/network/ssh/wire/internal/field_base.h"

namespace wire::internal {

template <typename T>
struct canonical_key_type : std::type_identity<T> {};

template <>
struct canonical_key_type<std::string_view> : std::type_identity<std::string> {};

template <typename T>
using canonical_key_type_t = canonical_key_type<T>::type;

template <typename T, EncodingOptions Opt>
struct field_impl : field_base {
  T value{};

  using value_type = T;
  static constexpr EncodingOptions encoding_options = Opt;

  field_impl() = default;
  field_impl(const field_impl& other) = default;
  field_impl(field_impl&& other) noexcept = default;
  field_impl& operator=(const field_impl&) = default;
  field_impl& operator=(field_impl&&) noexcept = default;

  constexpr field_impl(const T& t)
      : value(t) {}
  constexpr field_impl(T&& t)
      : value(std::move(t)) {}

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t limit) noexcept {
    try {
      return read_opt<Opt>(buffer, value, limit);
    } catch (const Envoy::EnvoyException& e) {
      return absl::InvalidArgumentError(e.what());
    }
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return write_opt<Opt>(buffer, value);
  }

  // implicit conversion operator: allow field<T> to be treated as T in some contexts
  constexpr operator T(this auto& self) { return self.value; }

  // arrow operator: allow using -> to access the value stored in a field
  constexpr auto* operator->(this auto& self) { return std::addressof(self.value); }

  // dereference operator: allow using * to access the value stored in a field
  constexpr auto& operator*(this auto& self) { return self.value; }

  // index operator: allow using [] to index into the vector of a field<vector<T>>
  constexpr auto& operator[](this auto& self, int i) { return self.value[i]; }

  // default comparison operators: comparing fields will compare their values
  constexpr auto operator<=>(const field_impl& other) const = default;
  constexpr bool operator==(const field_impl& other) const = default;

  // assignments to field<T> will assign T using its own assignment operators
  constexpr field_impl& operator=(const T& rhs) {
    value = rhs;
    return *this;
  }

  // moves to field<T> will assign T using its own move assignment operators
  constexpr field_impl& operator=(T&& rhs) {
    value = std::move(rhs);
    return *this;
  }

  // comparisons between field<T> and T will compare the values directly
  constexpr auto operator<=>(const T& other) const {
    return value <=> other;
  }

  // equality comparison between field<T> and T will compare the values directly
  constexpr bool operator==(const T& t) const {
    return value == t;
  }
};

namespace test {
struct Foo {};
struct Foo1 {
  uint16_t x;
};
struct Foo4 {
  uint32_t x;
};
struct Foo8 {
  uint64_t x;
};
struct Foo64 {
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
  uint64_t e;
  uint64_t f;
  uint64_t g;
  uint64_t h;
};
struct Attrs2 {
  uint32_t flags;
  uint64_t size;
  uint32_t uid;
  uint32_t gid;
  uint32_t permissions;
  uint32_t atime;
  uint32_t mtime;
  std::vector<Foo8> extended_data;

  constexpr bool operator==(const Attrs2&) const = default;
};
static_assert(sizeof(field_impl<uint32_t, None>{}) == sizeof(uint32_t));
static_assert(sizeof(field_impl<Foo, None>{}) == sizeof(Foo));
static_assert(sizeof(field_impl<Foo1, None>{}) == sizeof(Foo1));
static_assert(sizeof(field_impl<Foo4, None>{}) == sizeof(Foo4));
static_assert(sizeof(field_impl<Foo8, None>{}) == sizeof(Foo8));
static_assert(sizeof(field_impl<Foo64, None>{}) == sizeof(Foo64));
static_assert(sizeof(field_impl<Attrs2, None>{}) == sizeof(Attrs2));
} // namespace test

} // namespace wire::internal