#pragma once

#include <concepts>

#include "source/common/buffer/buffer_impl.h"

namespace {

class BytesViewBufferFragment : public Envoy::Buffer::BufferFragment {
public:
  BytesViewBufferFragment(const void* data, size_t size)
      : data_(data), size_(size) {}

  ~BytesViewBufferFragment() override {
    SECURITY_ASSERT(done_, "bug: buffer fragment was not released before it was destroyed "
                           "(was the temporary buffer from with_buffer_view moved?)");
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
// IMPORTANT: the callback must not extend the lifetime of the buffer passed to the callback (e.g.
// via Buffer::move()), as it holds a temporary fragment which is destroyed immediately after the
// callback returns. If this occurs, it will result in a panic.
// For example, the following is invalid:
//
//  Envoy::Buffer::OwnedImpl other_buffer;
//  bytes some_data;
//  with_buffer_view(some_data, [](Envoy::Buffer::Instance& tmp_buffer) {
//    other_buffer.move(tmp_buffer); // BAD! - This will panic
//  });
//
template <byteArrayLike T, typename F>
  requires std::invocable<F, Envoy::Buffer::Instance&>
decltype(auto) with_buffer_view(const T& b, F func) { // NOLINT(readability-identifier-naming)
  // initialization order is important here; the fragment must live longer than the buffer
  // (destructors are invoked in reverse order)
  BytesViewBufferFragment fragment(b.data(), b.size());
  Envoy::Buffer::OwnedImpl buffer;
  buffer.addBufferFragment(fragment);
  return func(buffer);
}
