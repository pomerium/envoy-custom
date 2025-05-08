#pragma once

#include "source/common/types.h"
#include <span>

// https://clang.llvm.org/docs/SafeBuffers.html
template <typename T>
constexpr std::span<T> unsafe_forge_span(T* pointer, size_t size) {
#pragma clang unsafe_buffer_usage begin
  return {pointer, size};
#pragma clang unsafe_buffer_usage end
}

template <typename T>
bytes_view linearizeToSpan(T& buffer) {
  auto length = buffer.length();
  return unsafe_forge_span(static_cast<uint8_t*>(buffer.linearize(static_cast<uint32_t>(length))), length);
}
