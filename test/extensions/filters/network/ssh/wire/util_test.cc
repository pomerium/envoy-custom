#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"
#include "gtest/gtest.h"

namespace wire::test {

TEST(UtilTest, WithBufferView) {
  const auto b = random_value<bytes>();
  auto sz = b.size();
  with_buffer_view(b, [&](Envoy::Buffer::Instance& buffer) {
    ASSERT_EQ(buffer.length(), b.size());
    ASSERT_EQ(b.data(), buffer.frontSlice().mem_);
    ASSERT_EQ(b.size(), buffer.frontSlice().len_);
    bytes b2(buffer.length(), 0);
    buffer.copyOut(0, buffer.length(), b2.data());
    EXPECT_EQ(b, b2);
  });
  EXPECT_EQ(sz, b.size());
}

TEST(UtilTest, WithBufferView_MovePanic) {
  const auto b = random_value<bytes>();
  Envoy::Buffer::OwnedImpl buf;
  EXPECT_DEATH(with_buffer_view(b, [&](Envoy::Buffer::Instance& buffer) {
                 buf.move(buffer);
               }),
               "bug: buffer fragment was not released before it was destroyed");
}

} // namespace wire::test