#pragma once

#include <vector>
#include <string>
#include <span>

#include "fmt/std.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage end

#include "source/common/bytes.h" // IWYU pragma: keep

using stream_id_t = uint64_t;

struct direction_t {
  char iv_tag;
  char key_tag;
  char mac_key_tag;
};

using namespace std::literals;

using string_list = std::vector<std::string>;

#pragma clang unsafe_buffer_usage begin
// https://clang.llvm.org/docs/SafeBuffers.html
template <typename T>
constexpr std::span<T> unsafe_forge_span(T* pointer, size_t size) {
  return {pointer, size};
}
#pragma clang unsafe_buffer_usage end
