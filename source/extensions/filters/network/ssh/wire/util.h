#pragma once

#include <concepts>
#include <vector>
#include <string>
#include <span>

#include "absl/status/statusor.h" // IWYU pragma: keep
#include "fmt/std.h"              // IWYU pragma: keep

#include "source/common/common/assert.h"
#include "source/common/buffer/buffer_impl.h"

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

inline bytes to_bytes(const auto& view) {
  return bytes{view.begin(), view.end()};
}

namespace {

class bytesViewBufferFragment : public Envoy::Buffer::BufferFragment {
public:
  bytesViewBufferFragment(const void* data, size_t size)
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
decltype(auto) with_buffer_view(const T& b, F func) {
  Envoy::Buffer::OwnedImpl buffer;
  bytesViewBufferFragment fragment(b.data(), b.size());
  buffer.addBufferFragment(fragment);
  return func(buffer);
}
