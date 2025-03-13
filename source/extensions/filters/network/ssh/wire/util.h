#pragma once

#include <algorithm>
#include <concepts>
#include <vector>
#include <string>
#include <span>

#include "absl/status/statusor.h" // IWYU pragma: keep
#include "fmt/std.h"              // IWYU pragma: keep

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

using namespace std::literals;

using bytes = std::vector<uint8_t>;

template <size_t N = std::dynamic_extent>
using bytes_view = std::span<const uint8_t, N>;

template <size_t N>
using fixed_bytes = std::array<uint8_t, N>;

template <size_t N>
using fixed_bytes_view = std::span<const uint8_t, N>;

using string_list = std::vector<std::string>;
using bytes_list = std::vector<bytes>;

inline bytes to_bytes(const auto& view) { // NOLINT
  return {view.begin(), view.end()};
}

inline bytes linearize_to_bytes(Envoy::Buffer::Instance& buffer, size_t len) { // NOLINT
  bytes out(len, 0);
  buffer.copyOut(0, len, out.data());
  return out;
}

#pragma clang unsafe_buffer_usage begin
// https://clang.llvm.org/docs/SafeBuffers.html
template <typename T>
constexpr std::span<T> unsafe_forge_span(T* pointer, size_t size) {
  return {pointer, size};
}
#pragma clang unsafe_buffer_usage end

// explicit_t can be used to prevent implicit conversions in non-constructor function args, by
// requiring that the type of the value passed by the caller is exactly the same as the requested
// type.
//
// This is primarily used in functions that accept size_t, but also a (possibly integral) template
// argument in another parameter, e.g.:
//  template <typename T>
//  void foo(T t, size_t size) { ... }
// or
//  template <typename... Ints>
//  void foo(size_t size, Ints... integers) { ... }
//
// Unsigned integer types <=64 bits can be implicitly converted to size_t, but size_t often has
// different semantic meaning than other int types. explicit_t<size_t> can be used to prevent
// mistakenly passing non-size_t values:
//  template <typename T>
//  void foo(T t, explicit_t<size_t> auto size) { ... }
//
//  template <typename... Ints>
//  void foo(explicit_t<size_t> auto size, Ints... integers) { ... }
//
template <typename T, typename U>
concept explicit_t = std::same_as<T, U>;

template <typename T>
concept explicit_size_t = explicit_t<size_t, T>;

namespace {

class BytesViewBufferFragment : public Envoy::Buffer::BufferFragment {
public:
  BytesViewBufferFragment(const void* data, size_t size)
      : data_(data), size_(size) {}

  const void* data() const override { return data_; }
  size_t size() const override { return size_; }
  void done() override {};

private:
  const void* data_;
  size_t size_;
};

template <typename T>
concept byteArrayLike = requires(T t) {
  { t.data() } -> std::convertible_to<const void*>;
  { t.size() } -> std::same_as<size_t>;
};

} // namespace

// with_buffer_view does the following:
// 1. creates a temporary Envoy::Buffer::Instance
// 2. adds a view over an existing string/bytes-like object to the buffer, as a non-owning fragment
// 3. calls the provided lambda function with that temporary buffer
// 4. forwards the value returned from the lambda to the caller
//
// This allows reading from an existing buffer via an Envoy::Buffer::Instance without copying the
// data to a temporary buffer. It is intended to be used as follows:
//
//  bytes some_data; // or string
//  ...
//  auto r = with_buffer_view(some_data, [](Envoy::Buffer::Instance& buffer) {
//    return something_that_reads_from_the_buffer(buffer);
//  })
//
template <byteArrayLike T, typename F>
  requires std::invocable<F, Envoy::Buffer::Instance&>
decltype(auto) with_buffer_view(const T& b, F func) { // NOLINT
  Envoy::Buffer::OwnedImpl buffer;
  BytesViewBufferFragment fragment(b.data(), b.size());
  buffer.addBufferFragment(fragment);
  return func(buffer);
}

// type_or_value_type<T> is equivalent to T, unless T is a vector<U>, in which case it will be
// equivalent to U. This is used to check that for some field<T>, T can be encoded/decoded; but
// lists are handled in a generic way, so we only need to check that the contents of the list
// can be encoded/decoded, not that specific list.
template <typename T>
struct type_or_value_type : std::type_identity<T> {};

template <typename T, typename Allocator>
struct type_or_value_type<std::vector<T, Allocator>> : std::type_identity<T> {};

template <typename T>
using type_or_value_type_t = type_or_value_type<T>::type;

// is_vector<T> is true if T is a vector of any type, otherwise false. This is used to enable
// decoding logic for fields of list types.
template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

// all_values_equal is true if every value in Actual is equal to Expected, otherwise false.
template <auto Expected, auto... Actual>
constexpr bool all_values_equal = ((Expected == Actual) && ...);

// values_unique returns true if there are no duplicates in the list, otherwise false.
template <typename T>
constexpr bool all_values_unique(std::initializer_list<T> arr) {
  for (size_t i = 0; i < arr.size(); ++i) {
    for (size_t j = i + 1; j < arr.size(); ++j) {
      if (*std::next(arr.begin(), i) == *std::next(arr.begin(), j)) {
        return false;
      }
    }
  }
  return true;
}

template <typename First, typename... Rest>
constexpr bool all_types_equal_to = (std::is_same_v<First, Rest> && ...);

template <typename... Rest>
constexpr bool all_types_equal = all_types_equal_to<Rest...>;

template <typename First, typename... Rest>
constexpr bool all_types_unique = sizeof...(Rest) == 0 ||
                                  ((!std::is_same_v<First, Rest> && ...) && all_types_unique<Rest...>);

template <typename T, typename... Ts>
struct index_of_type {
  static constexpr std::array<bool, sizeof...(Ts)> checks = {std::is_same_v<T, Ts>...};
  static constexpr size_t value = [] {
    auto it = std::find(checks.begin(), checks.end(), true);
    if (it == checks.end()) {
      static_assert("type not in list");
    }
    return std::distance(checks.begin(), it);
  }();
};

template <typename T, typename... Ts>
constexpr bool contains_type = (std::is_same_v<std::decay_t<T>, Ts> || ...);

template <typename... Ts>
struct first_type;

template <typename First, typename... Rest>
struct first_type<First, Rest...> : std::type_identity<First> {};

template <typename... Ts>
using first_type_t = first_type<Ts...>::type;

// used in std::visit to hold a list of lambda functions
// from https://en.cppreference.com/w/cpp/utility/variant/visit
template <typename... Ts>
struct overloads : Ts... {
  using Ts::operator()...;
};