#pragma once

#include "source/common/optref.h"
#include <source_location>

// Supplemental type traits

// callable_info can be used to obtain information about the return type and argument type of a
// callable object such as a lambda function.
template <typename T>
struct callable_info;

template <typename R, typename T, typename Arg>
struct callable_info<R (T::*)(Arg) const> {
  using return_type = R;
  using raw_arg_type = Arg;
  using arg_type_with_cv_optref = std::remove_reference_t<Arg>;
  using arg_type_with_cv = remove_optref_t<arg_type_with_cv_optref>;
  using arg_type = std::remove_cv_t<arg_type_with_cv>;
};

template <typename R, typename T>
struct callable_info<R (T::*)() const> {
  using return_type = R;
  using raw_arg_type = void;
  using arg_type_with_cv_optref = void;
  using arg_type_with_cv = void;
  using arg_type = void;
};

template <typename F>
using callable_info_t = callable_info<decltype(&std::decay_t<F>::operator())>;

template <typename F>
using callable_arg_type_t = callable_info_t<F>::arg_type;

// method_info can be used to obtain information about the return type and argument type(s) of
// a class member function.
template <typename F>
struct method_info;

// non-const methods
template <typename R, typename T, typename... Args>
struct method_info<R (T::*)(Args...)> {
  using return_type = R;
  using object_type = T;
  using args_type = std::tuple<Args...>;
  static constexpr bool is_const = false;
};

// const methods
template <typename R, typename T, typename... Args>
struct method_info<R (T::*)(Args...) const> {
  using return_type = R;
  using object_type = T;
  using args_type = std::tuple<Args...>;
  static constexpr bool is_const = true;
};

// generic_lambda_info can be used to detect whether a lambda function was defined with an argument
// type of 'auto', 'auto&, 'const auto&', or 'auto&&'. This is useful for validation purposes when
// working with std::visit.
template <typename F, typename Arg>
  requires (std::is_same_v<Arg, std::decay_t<Arg>> && std::is_invocable_v<F, Arg&>)
struct generic_lambda_info : callable_info<decltype(&F::template operator()<Arg>)> {
private:
  using base = callable_info<decltype(&F::template operator()<Arg>)>;

public:
  // [](const auto&) {...}
  static constexpr bool is_const_ref =
    std::is_same_v<std::add_lvalue_reference_t<std::add_const_t<Arg>>,
                   typename base::raw_arg_type>;

  // [](auto&) {...}
  static constexpr bool is_mutable_ref =
    std::is_same_v<std::add_lvalue_reference_t<Arg>,
                   typename base::raw_arg_type>;

  // [](auto&&) {...}
  static constexpr bool is_universal_ref =
    !is_const_ref &&
    !is_mutable_ref &&
    std::is_reference_v<typename base::raw_arg_type>;

  // if all of the above are false:
  // [](auto) {...}
  static constexpr bool is_plain = !is_const_ref && !is_mutable_ref && !is_universal_ref;
};

// type_or_value_type<T> is equivalent to T, unless T is a vector<U>, in which case it will be
// equivalent to U. This is used to check that for some field<T>, T can be encoded/decoded; but
// lists are handled in a generic way, so we only need to check that the contents of the list
// can be encoded/decoded, not that specific list.
template <typename T>
struct type_or_value_type : std::type_identity<T> {};

template <typename T, typename Allocator>
struct type_or_value_type<std::vector<T, Allocator>> : std::type_identity<T> {};

template <typename T>
using type_or_value_type_t = type_or_value_type<T>::type;

// index_of_type is used to obtain the index of a given type T within a type list.
template <typename T, typename... Ts>
struct index_of_type {
  static constexpr std::array<bool, sizeof...(Ts)> checks = {std::is_same_v<T, Ts>...};
  static constexpr size_t value = std::distance(checks.begin(), std::find(checks.begin(), checks.end(), true));
  static constexpr bool found = (value < sizeof...(Ts));
};

// specialization of index_of_type for an empty list
template <typename T>
struct index_of_type<T> {
  static constexpr size_t value = 0;
  static constexpr bool found = false;
};

// nth_type_t returns the type at index N in the given type list.
template <size_t N, typename... Ts>
using nth_type_t = std::tuple_element_t<N, std::tuple<Ts...>>;

// first_type_t is an alias for nth_type_t<0, ...>
template <typename... Ts>
using first_type_t = nth_type_t<0, Ts...>;

// conditional_const_t returns 'const T' if the given condition is true, otherwise 'T'.
template <bool Condition, typename T>
  requires (!std::is_const_v<T>)
using conditional_const_t = std::conditional_t<Condition, const T, T>;

// copy_reference_t copies the reference qualifiers of 'From' and applies them to 'To'.
// For example:
//  copy_reference_t<Foo, Bar> -> Bar
//  copy_reference_t<Foo&, Bar> -> Bar&
//  copy_reference_t<Foo&&, Bar> -> Bar&&
//  copy_reference_t<Foo, Bar&&> -> Bar
//  copy_reference_t<Foo, Bar&> -> Bar
template <typename From, typename To>
using copy_reference_t = std::conditional_t<
  std::is_rvalue_reference_v<From>,
  std::add_rvalue_reference_t<std::remove_reference_t<To>>,
  std::conditional_t<
    std::is_lvalue_reference_v<From>,
    std::add_lvalue_reference_t<std::remove_reference_t<To>>,
    std::remove_reference_t<To>>>;

// copy_const_t copies the const qualifier (or lack of) from 'From' and applies it to 'To'.
// For example:
//  copy_const_t<const Foo, Bar> -> const Bar
//  copy_const_t<Foo, Bar> -> Bar
//  copy_const_t<Foo, const Bar> -> const Bar
//  copy_const_t<const Foo, Bar&> -> const Bar&
//  copy_const_t<Foo, const Bar&> -> Bar&
template <typename From, typename To>
using copy_const_t = copy_reference_t<To,
                                      conditional_const_t<
                                        std::is_const_v<std::remove_reference_t<From>>,
                                        std::remove_const_t<std::remove_reference_t<To>>>>;

// all_values_equal is true if every value in Actual is equal to Expected, otherwise false.
template <auto Expected, auto... Actual>
constexpr bool all_values_equal = ((Expected == Actual) && ...);

// values_unique returns true if there are no duplicates in the list, otherwise false.
template <typename T>
consteval bool all_values_unique(std::initializer_list<T> arr) {
  for (size_t i = 0; i < arr.size(); ++i) {
    for (size_t j = i + 1; j < arr.size(); ++j) {
      if (*std::next(arr.begin(), i) == *std::next(arr.begin(), j)) {
        return false;
      }
    }
  }
  return true;
}

// all_types_equal_to returns true if all types in 'Rest' are the same as the type 'First', otherwise false.
template <typename First, typename... Rest>
constexpr bool all_types_equal_to = (std::is_same_v<First, Rest> && ...);

// all_types_equal returns true if all types in the given type list are the same, otherwise false.
template <typename... Rest>
constexpr bool all_types_equal = all_types_equal_to<Rest...>;

// contains_type returns true if type T appears in the type list Ts, otherwise false.
template <typename T, typename... Ts>
constexpr bool contains_type = index_of_type<T, Ts...>::found;

// is_vector<T> is true if T is a vector of any type, otherwise false.
template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

template <typename T>
static constexpr bool is_vector_v = is_vector<T>::value;

namespace detail {
#if defined(__clang__)
static constexpr auto type_name_prefix_str = "std::string_view type_name() [T = ";
static constexpr auto type_name_suffix_str = "]";
#elif defined(__GNUC__)
static constexpr auto type_name_prefix_str = "constexpr std::string_view type_name() [with T = ";
static constexpr auto type_name_suffix_str = "; std::string_view = std::basic_string_view<char>]";
#else
#error "unsupported compiler"
#endif
} // namespace detail

// Returns the string name of a type T. Used for debug logs and human-readable message formatting.
template <typename T>
constexpr std::string_view type_name() {
  std::string_view fn = std::source_location::current().function_name();
  fn.remove_prefix(std::char_traits<char>::length(detail::type_name_prefix_str));
  fn.remove_suffix(std::char_traits<char>::length(detail::type_name_suffix_str));
  return fn;
}