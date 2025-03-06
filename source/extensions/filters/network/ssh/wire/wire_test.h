#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace wire::test {

using testing::_;
using testing::Return;
using testing::Types;

struct mock_err_encoder {
  MOCK_METHOD(absl::StatusOr<size_t>, decode, (Envoy::Buffer::Instance&, size_t), (noexcept));
  MOCK_METHOD(absl::StatusOr<size_t>, encode, (Envoy::Buffer::Instance&), (const, noexcept));
};

} // namespace wire::test