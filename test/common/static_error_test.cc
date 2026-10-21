#include "source/common/static_error.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace test {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"

TEST(StaticErrorTest, FirstError) {
  EXPECT_STATIC_ASSERT(!first_error<static_error<"foo">{}>().ok());
  EXPECT_STATIC_ASSERT(first_error<static_error<"foo">{}>().message() == "foo");

  EXPECT_STATIC_ASSERT(first_error<no_error>().ok());
  EXPECT_STATIC_ASSERT(first_error<no_error>().message() == "");

  EXPECT_STATIC_ASSERT(!first_error<no_error, static_error<"foo">{}>().ok());
  EXPECT_STATIC_ASSERT(first_error<no_error, static_error<"foo">{}>().message() == "foo");

  EXPECT_STATIC_ASSERT(!first_error<static_error<"foo">{}, static_error<"bar">{}>().ok());
  EXPECT_STATIC_ASSERT(first_error<static_error<"foo">{}, static_error<"bar">{}>().message() == "foo");

  EXPECT_STATIC_ASSERT(!first_error<no_error, static_error<"foo">{}, static_error<"bar">{}>().ok());
  EXPECT_STATIC_ASSERT(first_error<no_error, static_error<"foo">{}, static_error<"bar">{}>().message() == "foo");

  EXPECT_STATIC_ASSERT(!first_error<no_error, no_error, static_error<"foo">{}, static_error<"bar">{}>().ok());
  EXPECT_STATIC_ASSERT(first_error<no_error, no_error, static_error<"foo">{}, static_error<"bar">{}>().message() == "foo");

  EXPECT_STATIC_ASSERT(first_error<no_error, no_error>().ok());
  EXPECT_STATIC_ASSERT(first_error<no_error, no_error>().message() == "");

  EXPECT_STATIC_ASSERT(!first_error<static_error<"foo">{}, static_error<"bar">{}, no_error>().ok());
  EXPECT_STATIC_ASSERT(first_error<static_error<"foo">{}, static_error<"bar">{}, no_error>().message() == "foo");
}

TEST(StaticErrorTest, StaticErrorf) {
  EXPECT_STATIC_ASSERT(static_errorf<"foo {}", static_string{"bar"}>().message() == "foo bar");
  EXPECT_STATIC_ASSERT(static_errorf<"foo {} {}", static_string{"bar"}, 1>().message() == "foo bar 1");
  EXPECT_STATIC_ASSERT(static_errorf<"foo {} {}", static_string{"bar"}, static_string{"baz"}>().message() == "foo bar baz");
  EXPECT_STATIC_ASSERT(static_errorf<"foo {} {}", static_string{"bar"}, static_errorf<"baz {}", 2>()>().message() == "foo bar baz 2");
}

#pragma clang diagnostic pop

} // namespace test