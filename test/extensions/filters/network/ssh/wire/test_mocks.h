#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "gmock/gmock.h" // IWYU pragma: keep

namespace wire::test {

class MockEncoder {
public:
  MOCK_METHOD(absl::StatusOr<size_t>, decode, (Envoy::Buffer::Instance&, size_t), (noexcept));
  MOCK_METHOD(absl::StatusOr<size_t>, encode, (Envoy::Buffer::Instance&), (const, noexcept));
};

} // namespace wire::test