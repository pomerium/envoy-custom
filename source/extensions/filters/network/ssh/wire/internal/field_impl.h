#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/buffer_io.h"

namespace wire::internal {

template <typename T>
struct canonical_key_type : std::type_identity<T> {};

template <>
struct canonical_key_type<std::string_view> : std::type_identity<std::string> {};

template <typename T>
using canonical_key_type_t = canonical_key_type<T>::type;

template <typename T, EncodingOptions Opt>
struct field_base {
  T value{};

  using value_type = T;
  static constexpr EncodingOptions encoding_options = Opt;

  field_base() = default;
  field_base(const field_base& other) = default;
  field_base(field_base&& other) noexcept = default;
  field_base& operator=(const field_base&) = default;
  field_base& operator=(field_base&&) noexcept = default;

  constexpr field_base(const T& t)
      : value(t) {}
  constexpr field_base(T&& t)
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
  constexpr auto operator<=>(const field_base& other) const = default;
  constexpr bool operator==(const field_base& other) const = default;

  // assignments to field<T> will assign T using its own assignment operators
  constexpr field_base& operator=(const T& rhs) {
    value = rhs;
    return *this;
  }

  // moves to field<T> will assign T using its own move assignment operators
  constexpr field_base& operator=(T&& rhs) {
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

} // namespace wire::internal