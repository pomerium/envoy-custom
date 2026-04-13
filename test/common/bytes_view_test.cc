#include "source/common/types.h"

#include "gtest/gtest.h"

using namespace std::literals;

TEST(BytesViewUtilsTest, StringViewToBytesView) {
  std::string foo{"foo"};
  std::string_view foo_view(foo);
  auto bv = to_bytes_view(foo_view);
  EXPECT_EQ(foo_view.size(), bv.size());
  EXPECT_EQ(static_cast<const void*>(foo_view.data()), static_cast<const void*>(bv.data()));
}

TEST(BytesViewUtilsTest, BytesViewToStringView) {
  std::string foo{"foo"};
  std::string_view foo_view(foo);

  auto foo_view2 = to_string_view(to_bytes_view(foo_view));
  ASSERT_EQ(foo_view, foo_view2);
  EXPECT_EQ(static_cast<const void*>(foo_view.data()), static_cast<const void*>(foo_view2.data()));
}

TEST(BytesViewUtilsTest, BytesLiteral) {
  auto b = "foo"_bytes;
  EXPECT_EQ(3, b.size());
  auto b_0 = "foo\0"_bytes;
  EXPECT_EQ(4, b_0.size());
}

TEST(BytesViewUtilsTest, ByteLiteral) {
  auto a = 'a'_byte;
  EXPECT_EQ(a, static_cast<uint8_t>('a'));
}

TEST(BytesViewUtilsTest, BytesViewLiteral) {
  const char* foo1 = "1234567890";
  auto foo2 = "1234567890"_bv;
  EXPECT_EQ(10, foo2.size());
  EXPECT_EQ(static_cast<const void*>(foo2.data()), static_cast<const void*>(foo1));
}

TEST(BytesViewUtilsTest, BytesViewEq) {
  bytes_view bv1_1 = "bv1"_bv;
  bytes_view bv1_2 = "bv1"_bv;
  bytes_view bv2 = "bv2"_bv;
  bytes_view bv3 = "bv3"_bv;
  bytes_view bv3_0 = "bv3\0"_bv;

  EXPECT_TRUE(bv1_1 == bv1_2);
  EXPECT_TRUE(bv1_1 != bv2);
  EXPECT_TRUE(bv2 != bv3);
  EXPECT_TRUE(bv3 != bv3_0);
}

TEST(BytesViewUtilsTest, BytesViewToString) {
  bytes_view foo = "foo"_bv;

  auto fooStr = to_string(foo);
  ASSERT_EQ(foo.size(), 3);
  ASSERT_EQ(foo.size(), fooStr.size());
  EXPECT_NE(static_cast<const void*>(foo.data()), static_cast<const void*>(fooStr.data()));

  auto fooStr2 = to_string(foo);
  EXPECT_NE(static_cast<const void*>(fooStr2.data()), static_cast<const void*>(fooStr.data()));

  bytes_view foo_0 = "foo\0"_bv;
  auto foo0Str = to_string(foo_0);
  ASSERT_EQ(foo_0.size(), 4);
  ASSERT_EQ(foo_0.size(), foo0Str.size());
  EXPECT_NE(static_cast<const void*>(foo_0.data()), static_cast<const void*>(foo0Str.data()));
}

TEST(BytesViewUtilsTest, ToBytes) {
  std::string foo_s = "foo"s;
  std::string_view foo_sv = "foo"sv;
  bytes_view foo_bv = "foo"_bv;
  bytes foo_b = "foo"_bytes;

  auto b1 = to_bytes(foo_s);
  auto b2 = to_bytes(foo_sv);
  auto b3 = to_bytes(foo_bv);
  auto b4 = to_bytes(foo_b);

  EXPECT_EQ(b1, b2);
  EXPECT_EQ(b1, b3);
  EXPECT_EQ(b1, b4);
  EXPECT_EQ(b2, b3);
  EXPECT_EQ(b2, b4);
  EXPECT_EQ(b3, b4);
}