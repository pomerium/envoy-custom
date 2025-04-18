#pragma once

namespace wire::test {

#define USE_MOCK_ENCODER                                                                         \
  class MockEncoder {                                                                            \
  public:                                                                                        \
    MOCK_METHOD(absl::StatusOr<size_t>, decode, (Envoy::Buffer::Instance&, size_t), (noexcept)); \
    MOCK_METHOD(absl::StatusOr<size_t>, encode, (Envoy::Buffer::Instance&), (const, noexcept));  \
  }

} // namespace wire::test