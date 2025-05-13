#include "source/common/span.h"
#include "gtest/gtest.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

TEST(SpanTest, UnsafeForgeSpan) {
  uint8_t* x = new uint8_t[10]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  auto span = unsafe_forge_span(x, 10);
  ASSERT_EQ(10, span.size());
  ASSERT_EQ(10, span.size_bytes());
  ASSERT_EQ(x, span.data());
}

TEST(SpanTest, LinearizeToSpan) {
  Envoy::Buffer::OwnedImpl buf;
  buf.add("\x01\x02\x03\x04\x05");
  ASSERT_EQ(5, buf.length());
  auto span = linearizeToSpan(buf);
  ASSERT_EQ(5, buf.length());
  ASSERT_EQ(5, span.size());
  ASSERT_EQ(1, span[0]);
  ASSERT_EQ(2, span[1]);
  ASSERT_EQ(3, span[2]);
  ASSERT_EQ(4, span[3]);
  ASSERT_EQ(5, span[4]);
  ASSERT_EQ(buf.linearize(buf.length()), span.data());
}