#pragma once

#include <algorithm>
#include <concepts>
#include <format>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>
#include <string>
#include <span>

#include "envoy/common/optref.h"

#include "fmt/std.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage end

using stream_id_t = uint64_t;

struct direction_t {
  char iv_tag;
  char key_tag;
  char mac_key_tag;
};

using namespace std::literals;

using bytes = std::vector<uint8_t>;

using bytes_view = std::span<const uint8_t>;

template <size_t N>
using fixed_bytes = std::array<uint8_t, N>;

template <size_t N>
using fixed_bytes_view = std::span<const uint8_t, N>;

using string_list = std::vector<std::string>;
using bytes_list = std::vector<bytes>;

inline constexpr bytes to_bytes(const auto& view) {
  return {view.begin(), view.end()};
}

#pragma clang unsafe_buffer_usage begin
// https://clang.llvm.org/docs/SafeBuffers.html
template <typename T>
constexpr std::span<T> unsafe_forge_span(T* pointer, size_t size) {
  return {pointer, size};
}
#pragma clang unsafe_buffer_usage end

// explicit_t can be used to prevent implicit conversions in non-constructor function args, by
// requiring that the type of the value passed by the caller is exactly the same as the requested
// type.
//
// This is primarily used in functions that accept size_t, but also a (possibly integral) template
// argument in another parameter, e.g.:
//  template <typename T>
//  void foo(T t, size_t size) { ... }
// or
//  template <typename... Ints>
//  void foo(size_t size, Ints... integers) { ... }
//
// Unsigned integer types <=64 bits can be implicitly converted to size_t, but size_t often has
// different semantic meaning than other int types. explicit_t<size_t> can be used to prevent
// mistakenly passing non-size_t values:
//  template <typename T>
//  void foo(T t, explicit_t<size_t> auto size) { ... }
//
//  template <typename... Ints>
//  void foo(explicit_t<size_t> auto size, Ints... integers) { ... }
//
template <typename T, typename U>
concept explicit_t = std::same_as<T, U>;

template <typename T>
concept explicit_size_t = explicit_t<size_t, T>;

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

// is_vector<T> is true if T is a vector of any type, otherwise false. This is used to enable
// decoding logic for fields of list types.
template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

// all_values_equal is true if every value in Actual is equal to Expected, otherwise false.
template <auto Expected, auto... Actual>
constexpr bool all_values_equal = ((Expected == Actual) && ...);

// values_unique returns true if there are no duplicates in the list, otherwise false.
template <typename T>
constexpr bool all_values_unique(std::initializer_list<T> arr) {
  for (size_t i = 0; i < arr.size(); ++i) {
    for (size_t j = i + 1; j < arr.size(); ++j) {
      if (*std::next(arr.begin(), i) == *std::next(arr.begin(), j)) {
        return false;
      }
    }
  }
  return true;
}

template <typename First, typename... Rest>
constexpr bool all_types_equal_to = (std::is_same_v<First, Rest> && ...);

template <typename... Rest>
constexpr bool all_types_equal = all_types_equal_to<Rest...>;

template <typename First, typename... Rest>
constexpr bool all_types_unique = sizeof...(Rest) == 0 ||
                                  ((!std::is_same_v<First, Rest> && ...) && all_types_unique<Rest...>);

template <typename T, typename... Ts>
struct index_of_type {
  static constexpr std::array<bool, sizeof...(Ts)> checks = {std::is_same_v<T, Ts>...};
  static constexpr size_t value = [] {
    auto it = std::find(checks.begin(), checks.end(), true);
    if (it == checks.end()) {
      static_assert("type not in list");
    }
    return std::distance(checks.begin(), it);
  }();
};

template <typename T, typename... Ts>
constexpr bool contains_type = (std::is_same_v<std::decay_t<T>, Ts> || ...);

template <size_t N, typename... Ts>
using nth_type_t = std::tuple_element_t<N, std::tuple<Ts...>>;

template <typename... Ts>
using first_type_t = nth_type_t<0, Ts...>;

template <typename T>
using opt_ref = std::optional<std::reference_wrapper<T>>;

template <typename T>
struct callable_info;

template <typename T>
struct remove_optref : std::type_identity<T> {};

template <typename T>
struct remove_optref<opt_ref<T>> : std::type_identity<T> {};

template <typename T>
struct remove_optref<Envoy::OptRef<T>> : std::type_identity<T> {};

template <typename T>
using remove_optref_t = remove_optref<T>::type;

template <bool Condition, typename T>
using conditional_const_t = std::conditional_t<Condition, const T, T>;

template <typename From, typename To>
using copy_reference_t = std::conditional_t<
  std::is_rvalue_reference_v<From>,
  std::add_rvalue_reference_t<std::remove_reference_t<To>>,
  std::conditional_t<
    std::is_lvalue_reference_v<From>,
    std::add_lvalue_reference_t<std::remove_reference_t<To>>,
    To>>;

template <typename R, typename T, typename Arg>
struct callable_info<R (T::*)(Arg) const> {
  using return_type = R;
  using raw_arg_type = Arg;
  using arg_type_with_cv_optref = std::remove_reference_t<Arg>;
  using arg_type_with_cv = remove_optref_t<arg_type_with_cv_optref>;
  using arg_type = std::remove_cv_t<arg_type_with_cv>;

  template <typename U>
  using copy_reference = copy_reference_t<Arg, U>;
};

template <typename F>
using visitor_info_t = callable_info<decltype(&std::decay_t<F>::operator())>;

template <typename F>
using visitor_arg_type_t = visitor_info_t<F>::arg_type;

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

template <bool IsConst, typename F>
struct const_validator {
  consteval static bool validate() {
    return !IsConst || std::is_const_v<typename visitor_info_t<std::remove_reference_t<F>>::arg_type_with_cv>;
  }
};

template <bool IsConst, typename F>
  requires std::same_as<std::decay_t<F>, F>
struct basic_visitor : F {
  static constexpr bool is_catchall_visitor = true;
  template <typename T>
  using arg_type_transform = T;

  static consteval void validate() {}
  using F::operator();
};

template <bool IsConst, typename F>
  requires std::same_as<std::decay_t<F>, F> && requires { typename visitor_info_t<F>; }
struct basic_visitor<IsConst, F> : F {
  static constexpr bool is_catchall_visitor = false;
  template <typename T>
  using arg_type_transform = T;

  static consteval void validate() {
    // this static_assert could be put into the body of the struct instead, but if it fails it
    // produces a thousand other incomprehensible errors; a failure here is much quieter
    if constexpr (!const_validator<IsConst, F>::validate()) {
      static_assert(false, "visited message is const-qualified, but handler has non-const argument type");
    }
  }

  using F::operator();
};

struct no_validation {};

// used in std::visit to hold a list of lambda functions
// from https://en.cppreference.com/w/cpp/utility/variant/visit
template <template <bool, typename> typename visitor_type,
          typename Self, typename... Fs>
struct overloads : visitor_type<std::is_const_v<std::remove_reference_t<Self>>, Fs>... {
  static constexpr bool is_const = std::is_const_v<std::remove_reference_t<Self>>;

  constexpr overloads(Fs... fs); // implemented out-of-line below

  constexpr overloads(no_validation, Fs... fs)
      : visitor_type<is_const, Fs>{fs}... {};

  using visitor_type<is_const, Fs>::operator()...;
};

template <template <bool, typename> typename visitor_type,
          typename Self, typename... Fs>
constexpr auto make_overloads(Fs... fs) {
  return overloads<visitor_type, Self, Fs...>{fs...};
}

template <template <bool, typename> typename visitor_type = basic_visitor,
          typename... Fs>
constexpr auto make_overloads_no_validation(Fs... fs) {
  return overloads<visitor_type, void, Fs...>{no_validation{}, fs...};
}

// Validates the argument types of the visitor lambdas to ensure that there is no unexpected
// behavior.
// std::visit requires the visitors to be exhaustive, meaning generally a "catch-all" visitor is
// needed (i.e. a lambda that accepts some form of 'auto' as its arg type). Unfortunately, this is
// quite error-prone: it is easy to mistakenly provide a catch-all visitor that is a better match
// for the input type than the actual visitor that should match that type. For example:
//  ExampleMsg msg;
//  msg.visit(
//   [](const ExampleMsg& msg) { ... }, <- will never be called
//   [](auto&) { ... }
//  );
//
template <template <bool, typename> typename visitor_type,
          typename Self>
  requires std::is_reference_v<Self>
struct overload_validator {
  static constexpr bool is_const = std::is_const_v<std::remove_reference_t<Self>>;

  template <typename... Fs>
  consteval static bool validate() {
    return validate_impl<Fs...>(std::index_sequence_for<Fs...>{});
  }

private:
  template <typename... Fs, size_t... Indexes>
  consteval static bool validate_impl(std::index_sequence<Indexes...>) {
    static_assert(sizeof...(Fs) == sizeof...(Indexes));
    static constexpr std::array<bool, sizeof...(Fs)> is_catchall = {visitor_type<is_const, Fs>::is_catchall_visitor...};
    constexpr auto num_catchall = std::count(std::begin(is_catchall), std::end(is_catchall), true);
    if constexpr (num_catchall > 0) {
      // static_assert(sizeof...(Indexes) > 1, "invalid visit: must use at least one non-catchall handler");
      constexpr size_t last_catchall_idx =
        std::distance(std::begin(is_catchall), std::find(std::rbegin(is_catchall), std::rend(is_catchall), true).base()) - 1;

      return ([] {
        using last_catchall_type = nth_type_t<last_catchall_idx, Fs...>;
        if constexpr (!is_catchall.at(Indexes)) {
          return validate_one<Fs, last_catchall_type>();
        }
        return true;
      }() && ...);
    }
    return true;
  }

  template <typename F, typename Catchall>
  consteval static bool validate_one() {
    // test that f will always be selected over the catchall
    using f_info = visitor_info_t<F>;
    using f_visitor_type = visitor_type<is_const, std::decay_t<F>>;
    // 1. remove references from the original arg type
    // 2. apply arg_type_transform from the visitor
    // 3. add back the original reference qualifiers
    using f_arg_type = typename f_info::template copy_reference<
      typename f_visitor_type::template arg_type_transform<
        typename f_info::arg_type_with_cv>>;

    using catchall_info = generic_lambda_info<Catchall, std::decay_t<f_arg_type>>;
    conditional_const_t<is_const, std::decay_t<f_arg_type>> arg;
    if constexpr (catchall_info::is_const_ref) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) { return true; },
        [](const auto&) { return false; })(std::forward_like<Self>(arg));
    } else if constexpr (catchall_info::is_mutable_ref) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) { return true; },
        [](auto&) { return false; })(std::forward_like<Self>(arg));
    } else if constexpr (catchall_info::is_universal_ref) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) { return true; },
        [](auto&&) { return false; })(std::forward_like<Self>(arg));
    } else if constexpr (catchall_info::is_plain) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) { return true; },
        [](auto) { return false; })(std::forward_like<Self>(arg));
    }
    static_assert("unreachable");
  }
};

template <template <bool, typename> typename visitor_type,
          typename Self, typename... Fs>
constexpr overloads<visitor_type, Self, Fs...>::overloads(Fs... fs)
    : visitor_type<is_const, Fs>{fs}... {
  if consteval {
    (visitor_type<is_const, Fs>::validate(), ...);
    if constexpr (!overload_validator<visitor_type, Self>::template validate<Fs...>()) {
      static_assert(false,
                    "invalid visit: one or more functions would never be called for its intended type "
                    "because the catch-all function is a better candidate");
    }
  }
}

template <typename T, typename... U>
concept any_of = (std::same_as<T, std::decay_t<U>> || ...);

constexpr inline absl::Status statusf(std::format_string<std::string_view> str, absl::Status underlying) {
  std::string_view msg = underlying.message();
  return absl::Status(static_cast<absl::StatusCode>(underlying.raw_code()),
                      fmt::vformat(str.get(), fmt::make_format_args(msg)));
}

constexpr inline std::pair<std::string_view, std::string_view> status_code_strings(absl::StatusCode c) {
  switch (c) {
  case absl::StatusCode::kOk:
    return {"OK",
            "OK"};
  case absl::StatusCode::kCancelled:
    return {"CANCELLED",
            "Cancelled"}; // [sic] match length of absl status code
  case absl::StatusCode::kUnknown:
    return {"UNKNOWN",
            "Unknown"};
  case absl::StatusCode::kInvalidArgument:
    return {"INVALID_ARGUMENT",
            "Invalid Argument"};
  case absl::StatusCode::kDeadlineExceeded:
    return {"DEADLINE_EXCEEDED",
            "Deadline Exceeded"};
  case absl::StatusCode::kNotFound:
    return {"NOT_FOUND",
            "Not Found"};
  case absl::StatusCode::kAlreadyExists:
    return {"ALREADY_EXISTS",
            "Already Exists"};
  case absl::StatusCode::kPermissionDenied:
    return {"PERMISSION_DENIED",
            "Permission Denied"};
  case absl::StatusCode::kResourceExhausted:
    return {"RESOURCE_EXHAUSTED",
            "Resource Exhausted"};
  case absl::StatusCode::kFailedPrecondition:
    return {"FAILED_PRECONDITION",
            "Failed Precondition"};
  case absl::StatusCode::kAborted:
    return {"ABORTED",
            "Aborted"};
  case absl::StatusCode::kOutOfRange:
    return {"OUT_OF_RANGE",
            "Out Of Range"};
  case absl::StatusCode::kUnimplemented:
    return {"UNIMPLEMENTED",
            "Unimplemented"};
  case absl::StatusCode::kInternal:
    return {"INTERNAL",
            "Internal"};
  case absl::StatusCode::kUnavailable:
    return {"UNAVAILABLE",
            "Unavailable"};
  case absl::StatusCode::kDataLoss:
    return {"DATA_LOSS",
            "Data Loss"};
  case absl::StatusCode::kUnauthenticated:
    return {"UNAUTHENTICATED",
            "Unauthenticated"};
  default:
    return {"", ""};
  }
}

constexpr inline std::string_view status_code_to_string(absl::StatusCode c) {
  return status_code_strings(c).second;
}

inline std::string statusToString(const absl::Status& stat) {
  auto str = stat.ToString();
  if (stat.ok()) {
    return str;
  }
  auto [abslName, newName] = status_code_strings(stat.code());
  if (!abslName.empty()) {
    str.replace(0, abslName.size(), newName);
  } else {
    // replace the empty string with something more useful
    str.insert(0, fmt::format("Code({})", stat.raw_code()));
  }
  if (str.ends_with(": ") && stat.message().empty()) {
    // trim empty message
    str.resize(str.size() - 2);
  }
  return str;
}
