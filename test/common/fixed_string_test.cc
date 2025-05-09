#include "source/common/fixed_string.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace test {

template <fixed_string S>
struct Foo {
  static constexpr std::string_view value = S.to_string();
};

TEST(FixedStringTest, FixedString) {
  static constinit auto str1 = Foo<"test">{};
  static_assert(str1.value == "test"sv);

  static_assert(fixed_string("").to_string() == ""sv);
  static_assert(fixed_string("test").to_string() == "test"sv);
  static_assert(fixed_string("test") == fixed_string("test"));
  static_assert(fixed_string("test") != fixed_string("test1"));
  static_assert(fixed_string("foo1") != fixed_string("foo2"));
  EXPECT_STATIC_ASSERT(fixed_string("a") == fixed_string("a"));
  EXPECT_STATIC_ASSERT(fixed_string("b") != fixed_string("a"));
  EXPECT_STATIC_ASSERT(fixed_string("bb") != fixed_string("a"));
  EXPECT_STATIC_ASSERT(fixed_string("b") > fixed_string("a"));
  EXPECT_STATIC_ASSERT(fixed_string("bb") > fixed_string("a"));
  EXPECT_STATIC_ASSERT(fixed_string("b") >= fixed_string("a"));
  EXPECT_STATIC_ASSERT(fixed_string("b") >= fixed_string("aa"));
  EXPECT_STATIC_ASSERT(fixed_string("a") < fixed_string("b"));
  EXPECT_STATIC_ASSERT(fixed_string("a") < fixed_string("bb"));
  EXPECT_STATIC_ASSERT(fixed_string("a") <= fixed_string("b"));
  EXPECT_STATIC_ASSERT(fixed_string("ab") <= fixed_string("b"));
}

} // namespace test