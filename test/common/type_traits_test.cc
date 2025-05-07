#include "source/common/type_traits.h"
#include "source/common/optref.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace test {

TEST(TypeTraitsTest, CallableInfo) {
  class Message1 {};
  class Message2 {};
  class Message3 {};

  auto non_overload = [&](const Message1& _) {
    return 1;
  };
  auto overload = [&](opt_ref<const Message2> _) {
    return 2;
  };

  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(non_overload)>::raw_arg_type, const Message1&>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(non_overload)>::arg_type_with_cv, const Message1>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(non_overload)>::arg_type, Message1>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(non_overload)>::arg_type_with_cv_optref, const Message1>);

  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(overload)>::raw_arg_type, opt_ref<const Message2>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(overload)>::arg_type_with_cv_optref, opt_ref<const Message2>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(overload)>::arg_type_with_cv, const Message2>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(overload)>::arg_type, Message2>);
}
TEST(TypeTraitsTest, FunctionInfo) {
  class Test {
  public:
    int foo(std::string, const int&);
  };
  EXPECT_STATIC_ASSERT(std::is_same_v<function_info<decltype(&Test::foo)>::return_type, int>);
  EXPECT_STATIC_ASSERT(std::is_same_v<function_info<decltype(&Test::foo)>::object_type, Test>);
  EXPECT_STATIC_ASSERT(std::is_same_v<function_info<decltype(&Test::foo)>::args_type, std::tuple<std::string, const int&>>);
}

TEST(TypeTraitsTest, GenericLambdaInfo) {
  class Message1 {};

  enum Result {
    CalledDefaultAutoRef,
    CalledDefaultConstAutoRef,
    CalledDefaultAutoUniversalRef,
    CalledDefaultAutoPlain,
  };

  auto defaultAutoRef = [](auto&) { return CalledDefaultAutoRef; };
  auto defaultConstAutoRef = [](const auto&) { return CalledDefaultConstAutoRef; };
  auto defaultAutoUniversalRef = [](auto&&) { return CalledDefaultAutoUniversalRef; };
  auto defaultAutoPlain = [](auto) { return CalledDefaultAutoPlain; };

  EXPECT_STATIC_ASSERT(generic_lambda_info<decltype(defaultConstAutoRef), Message1>::is_const_ref);
  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultConstAutoRef), Message1>::is_mutable_ref);
  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultConstAutoRef), Message1>::is_universal_ref);

  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoRef), Message1>::is_const_ref);
  EXPECT_STATIC_ASSERT(generic_lambda_info<decltype(defaultAutoRef), Message1>::is_mutable_ref);
  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoRef), Message1>::is_universal_ref);

  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoUniversalRef), Message1>::is_const_ref);
  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoUniversalRef), Message1>::is_mutable_ref);
  EXPECT_STATIC_ASSERT(generic_lambda_info<decltype(defaultAutoUniversalRef), Message1>::is_universal_ref);

  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoPlain), Message1>::is_const_ref);
  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoPlain), Message1>::is_mutable_ref);
  EXPECT_STATIC_ASSERT(!generic_lambda_info<decltype(defaultAutoPlain), Message1>::is_universal_ref);
}

TEST(TypeTraitsTest, TypeOrValueType) {
  EXPECT_STATIC_ASSERT(std::is_same_v<type_or_value_type_t<int>, int>);
  EXPECT_STATIC_ASSERT(std::is_same_v<type_or_value_type_t<std::vector<int>>, int>);
}

TEST(TypeTraitsTest, IndexOfType) {
  EXPECT_STATIC_ASSERT(index_of_type<int, int, char, std::string>::value == 0);
  EXPECT_STATIC_ASSERT(index_of_type<int, int, char, std::string>::found);
  EXPECT_STATIC_ASSERT(index_of_type<char, int, char, std::string>::value == 1);
  EXPECT_STATIC_ASSERT(index_of_type<char, int, char, std::string>::found);
  EXPECT_STATIC_ASSERT(index_of_type<std::string, int, char, std::string>::value == 2);
  EXPECT_STATIC_ASSERT(index_of_type<std::string, int, char, std::string>::found);

  EXPECT_STATIC_ASSERT(index_of_type<bool, int, char, std::string>::value == 3);
  EXPECT_STATIC_ASSERT(!index_of_type<bool, int, char, std::string>::found);
  EXPECT_STATIC_ASSERT(index_of_type<std::nullptr_t, int, char, std::string>::value == 3);
  EXPECT_STATIC_ASSERT(!index_of_type<std::nullptr_t, int, char, std::string>::found);

  EXPECT_STATIC_ASSERT(index_of_type<int>::value == 0);
  EXPECT_STATIC_ASSERT(!index_of_type<int>::found);

  EXPECT_STATIC_ASSERT(index_of_type<int, char>::value == 1);
  EXPECT_STATIC_ASSERT(!index_of_type<int, char>::found);
}

TEST(TypeTraitsTest, NthType) {
  EXPECT_STATIC_ASSERT(std::is_same_v<nth_type_t<0, int, char, std::string>, int>);
  EXPECT_STATIC_ASSERT(std::is_same_v<nth_type_t<1, int, char, std::string>, char>);
  EXPECT_STATIC_ASSERT(std::is_same_v<nth_type_t<2, int, char, std::string>, std::string>);
  // EXPECT_STATIC_ASSERT(std::is_same_v<nth_type_t<3, int, char, std::string>, void>); // shouldn't compile
  EXPECT_STATIC_ASSERT(std::is_same_v<first_type_t<int, char>, int>)
  // EXPECT_STATIC_ASSERT(std::is_same_v<first_type_t<>, int>) // shouldn't compile
}

TEST(TypeTraitsTest, ConditionalConst) {
  EXPECT_STATIC_ASSERT(std::is_same_v<conditional_const_t<true, int>, const int>);
  // EXPECT_STATIC_ASSERT(std::is_same_v<conditional_const_t<true, const int>, const int>) // shouldn't compile
  EXPECT_STATIC_ASSERT(std::is_same_v<conditional_const_t<false, int>, int>);
}

TEST(TypeTraitsTest, CopyReference) {
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int, int>, int>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int&, int>, int&>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int&&, int>, int&&>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int, int&>, int>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int&, int&>, int&>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int&&, int&>, int&&>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int, int&&>, int>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int&, int&&>, int&>);
  EXPECT_STATIC_ASSERT(std::is_same_v<copy_reference_t<int&&, int&&>, int&&>);
}

TEST(TypeTraitsTest, AllValuesEqual) {
  EXPECT_STATIC_ASSERT(all_values_equal<1, 1, 1>);
  EXPECT_STATIC_ASSERT(all_values_equal<1>);
  EXPECT_STATIC_ASSERT(!all_values_equal<1, 1, 2>);
  EXPECT_STATIC_ASSERT(!all_values_equal<1, 2, 1>);
  EXPECT_STATIC_ASSERT(!all_values_equal<1, 2, 2>);
  // EXPECT_STATIC_ASSERT(!all_values_equal<>) // shouldn't compile
}

TEST(TypeTraitsTest, AllValuesUnique) {
  static_assert(all_values_unique({1, 2, 3}));
  static_assert(!all_values_unique({1, 2, 2}));
  static_assert(all_values_unique({1, 2}));
  static_assert(!all_values_unique({1, 1}));
  static_assert(all_values_unique({1}));
  static_assert(all_values_unique<int>({}));
}

TEST(TypeTraitsTest, AllTypesEqualTo) {
  EXPECT_STATIC_ASSERT(all_types_equal_to<int, int, int>);
  EXPECT_STATIC_ASSERT(!all_types_equal_to<int, int, char>);
  EXPECT_STATIC_ASSERT(!all_types_equal_to<char, int, char>);
  EXPECT_STATIC_ASSERT(!all_types_equal_to<char, int, int>);
  EXPECT_STATIC_ASSERT(!all_types_equal_to<int, char, char>);
  EXPECT_STATIC_ASSERT(all_types_equal_to<int, int>);
  EXPECT_STATIC_ASSERT(!all_types_equal_to<int, char>);
  // EXPECT_STATIC_ASSERT(!all_types_equal_to<int>); // shouldn't compile
}

TEST(TypeTraitsTest, AllTypesEqual) {
  EXPECT_STATIC_ASSERT(all_types_equal<int, int, int>);
  EXPECT_STATIC_ASSERT(!all_types_equal<int, int, char>);
  EXPECT_STATIC_ASSERT(!all_types_equal<int, char, char>);
  EXPECT_STATIC_ASSERT(all_types_equal<int, int>);
  EXPECT_STATIC_ASSERT(all_types_equal<int>);
  // EXPECT_STATIC_ASSERT(all_types_equal<>); // shouldn't compile
}

TEST(TypeTraitsTest, IsVector) {
  EXPECT_STATIC_ASSERT(!is_vector_v<int>);
  EXPECT_STATIC_ASSERT(!is_vector_v<void>);
  EXPECT_STATIC_ASSERT(is_vector_v<std::vector<int>>);
  EXPECT_STATIC_ASSERT(!is_vector_v<std::list<int>>);
  EXPECT_STATIC_ASSERT(is_vector_v<std::vector<void>>);
  EXPECT_STATIC_ASSERT(is_vector_v<std::vector<int, std::allocator<int>>>);
  EXPECT_STATIC_ASSERT(is_vector_v<std::vector<int, std::allocator<void>>>);
}

#define STR_(x) #x
#define STR(x) STR_(x)
TEST(TypeTraitsTest, TypeName) {
  EXPECT_STATIC_ASSERT(type_name<int>() == "int");
  EXPECT_STATIC_ASSERT(type_name<void>() == "void");
  EXPECT_STATIC_ASSERT(type_name<std::string>() == "std::string");
  EXPECT_STATIC_ASSERT(type_name<::std::string>() == "std::string");
  using std::string_view;
  EXPECT_STATIC_ASSERT(type_name<string_view>() == "std::string_view");
  EXPECT_STATIC_ASSERT(type_name<std::vector<int>>() == "std::vector<int>");
  EXPECT_STATIC_ASSERT(type_name<std::tuple<int, char>>() == "std::tuple<int, char>");
  EXPECT_STATIC_ASSERT(type_name<std::tuple<>>() == "std::tuple<>");
  EXPECT_STATIC_ASSERT(type_name<char[2]>() == "char[2]");
  EXPECT_STATIC_ASSERT(type_name<decltype(1)>() == "int");
  EXPECT_STATIC_ASSERT(type_name<decltype([] {})>() == "(lambda at " __FILE__ ":" STR(__LINE__) ":3)");
  EXPECT_STATIC_ASSERT(type_name<int&&>() == "int &&");
  EXPECT_STATIC_ASSERT(type_name<const int>() == "const int");
  EXPECT_STATIC_ASSERT(type_name<const int&>() == "const int &");
  EXPECT_STATIC_ASSERT(type_name<volatile int>() == "volatile int");
  EXPECT_STATIC_ASSERT(type_name<const volatile int>() == "const volatile int");
}

} // namespace test