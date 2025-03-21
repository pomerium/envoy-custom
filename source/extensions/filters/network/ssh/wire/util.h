#pragma once

#include <concepts>

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

namespace {

class BytesViewBufferFragment : public Envoy::Buffer::BufferFragment {
public:
  BytesViewBufferFragment(const void* data, size_t size)
      : data_(data), size_(size) {}

  ~BytesViewBufferFragment() override {
    SECURITY_ASSERT(done_, "bug: with_buffer_view() callback must drain the temporary buffer");
  }
  const void* data() const override { return data_; }
  size_t size() const override { return size_; }
  void done() override { done_ = true; };

private:
  const void* data_;
  size_t size_;
  bool done_{false};
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
// IMPORTANT: the callback must drain all bytes from the temporary buffer before it returns,
// otherwise this will panic.
template <byteArrayLike T, typename F>
  requires std::invocable<F, Envoy::Buffer::Instance&>
decltype(auto) with_buffer_view(const T& b, F func) { // NOLINT
  // initialization order is important here; the fragment must live longer than the buffer
  // (destructors are invoked in reverse order)
  BytesViewBufferFragment fragment(b.data(), b.size());
  Envoy::Buffer::OwnedImpl buffer;
  buffer.addBufferFragment(fragment);
  return func(buffer);
}
