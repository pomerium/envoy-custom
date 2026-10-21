#include "source/common/static_string.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace test {

template <static_string S>
struct Foo {
  static constexpr std::string_view value = static_cast<std::string_view>(S);
};

TEST(StaticStringTest, StaticString) {
  static constinit auto str1 = Foo<"test">{};
  EXPECT_STATIC_ASSERT(str1.value == "test"sv);

  EXPECT_STATIC_ASSERT(static_cast<std::string_view>(static_string("")) == ""sv);
  EXPECT_STATIC_ASSERT(static_cast<std::string_view>(static_string("test")) == "test"sv);
  EXPECT_STATIC_ASSERT(static_string("test") == static_string("test"));
  EXPECT_STATIC_ASSERT(static_string("test") != static_string("test1"));
  EXPECT_STATIC_ASSERT(static_string("foo1") != static_string("foo2"));
  EXPECT_STATIC_ASSERT(static_string("a") == static_string("a"));
  EXPECT_STATIC_ASSERT(static_string("b") != static_string("a"));
  EXPECT_STATIC_ASSERT(static_string("bb") != static_string("a"));
  EXPECT_STATIC_ASSERT(static_string("b") > static_string("a"));
  EXPECT_STATIC_ASSERT(static_string("bb") > static_string("a"));
  EXPECT_STATIC_ASSERT(static_string("b") >= static_string("a"));
  EXPECT_STATIC_ASSERT(static_string("b") >= static_string("aa"));
  EXPECT_STATIC_ASSERT(static_string("a") < static_string("b"));
  EXPECT_STATIC_ASSERT(static_string("a") < static_string("bb"));
  EXPECT_STATIC_ASSERT(static_string("a") <= static_string("b"));
  EXPECT_STATIC_ASSERT(static_string("ab") <= static_string("b"));

  EXPECT_STATIC_ASSERT(static_string("ab") == "ab");
  EXPECT_STATIC_ASSERT(static_string("ab") != "ba");
  EXPECT_STATIC_ASSERT(static_string("") == "");
  EXPECT_STATIC_ASSERT(sizeof(static_string("ab")) == 3);
  EXPECT_STATIC_ASSERT(static_string("ab") == "ab"sv);
  EXPECT_STATIC_ASSERT(static_string("ab") != "ab\0"sv);

  EXPECT_STATIC_ASSERT(static_string{"test"}.size() == 4);
  EXPECT_STATIC_ASSERT(std::to_array(static_string{"test"}.value) == std::array<char, 5>{'t', 'e', 's', 't', '\0'});
  EXPECT_STATIC_ASSERT(std::to_array(static_string<4>(std::string_view("test")).value) == std::array<char, 5>{'t', 'e', 's', 't', '\0'});

  static constexpr auto s = static_string("test");
  EXPECT_STATIC_ASSERT(std::char_traits<char>::length(s.data()) == 4);
  EXPECT_STATIC_ASSERT(s.size() == 4);

  EXPECT_EQ(std::string("foo bar"), fmt::format("foo {}", static_string{"bar"}));
  EXPECT_EQ("test"sv, static_string{"test"});
  std::stringstream stream;
  stream << static_string{"foo"};
  EXPECT_EQ("foo"s, stream.str());
}

namespace {
template <auto> struct test_helper;
}
template <size_t N>
concept test_string_view_constructor_compiles_with_n = requires { typename test_helper<static_string<N>{"test"sv}>; };

TEST(StaticStringTest, StaticString_StringViewConstructor) {
  // test that when constructing a static_string from a constexpr string_view, it will not compile
  // if the string_view's size does not match N, since it cannot be deduced automatically
  EXPECT_STATIC_ASSERT(test_string_view_constructor_compiles_with_n<4>);
  EXPECT_STATIC_ASSERT(!test_string_view_constructor_compiles_with_n<5>);

  static constexpr auto s = static_string<4>("test"sv);
  EXPECT_STATIC_ASSERT(std::char_traits<char>::length(s.data()) == 4);
  EXPECT_STATIC_ASSERT(s.size() == 4);
}

} // namespace test