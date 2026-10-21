#pragma once

#include <algorithm>
#include <concepts>
#include <type_traits>
#include <variant>

#include "source/common/concepts.h"
#include "source/common/static_error.h"
#include "source/common/type_traits.h"

namespace tags {
struct no_validation {};
} // namespace tags

using namespace std::literals;

template <typename T>
static constexpr bool is_tag_no_validation = std::is_base_of_v<tags::no_validation, std::decay_t<T>>;

template <typename... Args>
static constexpr bool contains_tag_no_validation = (is_tag_no_validation<Args> || ...);

template <typename Self, typename F>
struct const_validator {
  consteval static decltype(auto) validate() {
    static constexpr bool is_const = std::is_const_v<std::remove_reference_t<Self>>;
    using arg_type = typename callable_info_t<F>::arg_type_with_cv;
    if constexpr (is_const && !std::is_const_v<arg_type>) {
      return static_errorf<"visited message is const-qualified, but handler has non-const argument type '{}'", type_name<arg_type>()>();
    } else {
      return no_error;
    }
  }
};

// Used in the definition of a 'visitor' object; instead of inheriting directly from lambda types,
// each type inherited from can be 'enriched' by wrapping it in basic_visitor<>. See [overloads]
// for usage.
template <typename Self, typename F>
  requires std::same_as<std::decay_t<F>, F>
struct basic_visitor : F {
  static constexpr bool is_catchall_visitor = true;
  template <DecayedType T>
  using arg_type_transform = T;

  static consteval decltype(auto) validate() {
    return no_error;
  }
  using F::operator();
};

template <typename Self, typename F>
  requires std::same_as<std::decay_t<F>, F> && requires { typename callable_info_t<F>; }
struct basic_visitor<Self, F> : F {
  static constexpr bool is_catchall_visitor = false;
  template <DecayedType T>
  using arg_type_transform = T;

  static consteval decltype(auto) validate() {
    return const_validator<Self, F>::validate();
  }

  using F::operator();
};

// used in std::visit to hold a list of lambda functions
// from https://en.cppreference.com/w/cpp/utility/variant/visit
template <template <typename, typename> typename visitor_type,
          typename Self, typename... Fs>
struct overloads : visitor_type<Self, Fs>... {

  constexpr overloads(Fs... fs); // implemented out-of-line below

  constexpr overloads(tags::no_validation, Fs... fs)
      : visitor_type<Self, Fs>{fs}... {};

  using visitor_type<Self, Fs>::operator()...;
};

template <template <typename, typename> typename visitor_type,
          typename Self, typename... Fs>
constexpr auto make_overloads(Fs... fs) {
  return overloads<visitor_type, Self, Fs...>{fs...};
}

template <template <typename, typename> typename visitor_type = basic_visitor,
          typename... Fs>
constexpr auto make_overloads_no_validation(Fs... fs) {
  return overloads<visitor_type, void, Fs...>{tags::no_validation{}, fs...};
}

template <typename Variant, typename... Fs>
constexpr auto basic_visit(Variant&& v, Fs... fs) {
  return std::visit(make_overloads<basic_visitor, Variant>(fs...), std::forward<Variant>(v));
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
template <template <typename, typename> typename visitor_type,
          typename Self>
  requires std::is_reference_v<Self>
struct overload_validator {
  static constexpr bool is_const = std::is_const_v<std::remove_reference_t<Self>>;

  template <typename... Fs>
  consteval static decltype(auto) validate() {
    return validate_impl<Fs...>(std::index_sequence_for<Fs...>{});
  }

private:
  template <typename... Fs, size_t... Indexes>
  consteval static decltype(auto) validate_impl(std::index_sequence<Indexes...>) {
    static_assert(sizeof...(Fs) == sizeof...(Indexes));
    static constexpr std::array<bool, sizeof...(Fs)> is_catchall = {visitor_type<Self, Fs>::is_catchall_visitor...};
    constexpr auto num_catchall = std::count(std::begin(is_catchall), std::end(is_catchall), true);
    if constexpr (num_catchall > 0) {
      // static_assert(sizeof...(Indexes) > 1, "invalid visit: must use at least one non-catchall handler");
      constexpr size_t last_catchall_idx =
        std::distance(std::begin(is_catchall), std::find(std::rbegin(is_catchall), std::rend(is_catchall), true).base()) - 1;

      return first_error<
        [] constexpr {
          using last_catchall_type = nth_type_t<last_catchall_idx, Fs...>;
          if constexpr (!is_catchall.at(Indexes)) {
            if constexpr (!validate_one<Fs, last_catchall_type>()) {
              return static_errorf<"invalid visit: function with argument '{}' would never be called "
                                   "because the catch-all function is a better candidate",
                                   type_name<typename callable_info_t<Fs>::raw_arg_type>()>();
            } else {
              return no_error;
            }
          } else {
            return no_error;
          }
        }()...>();
    } else {
      return no_error;
    }
  }

  template <typename F, typename Catchall>
  consteval static bool validate_one() {
    // test that f will always be selected over the catchall
    using f_info = callable_info_t<F>;
    using f_visitor_type = visitor_type<Self, std::decay_t<F>>;
    // 1. remove const and references from the original arg type
    // 2. apply arg_type_transform from the visitor
    // 3. add back the original const qualifier if any
    // 4. add back the original reference qualifiers
    using f_arg_type = copy_reference_t<typename f_info::raw_arg_type,
                                        copy_const_t<
                                          typename f_info::arg_type_with_cv,
                                          typename f_visitor_type::template arg_type_transform<
                                            typename f_info::arg_type>>>;

    using catchall_info = generic_lambda_info<Catchall, std::decay_t<f_arg_type>>;
    conditional_const_t<is_const, std::decay_t<f_arg_type>> arg;
    if constexpr (catchall_info::is_const_ref) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) consteval { return true; },
        [](const auto&) consteval { return false; })(std::forward_like<Self>(arg));
    } else if constexpr (catchall_info::is_mutable_ref) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) consteval { return true; },
        [](auto&) consteval { return false; })(std::forward_like<Self>(arg));
    } else if constexpr (catchall_info::is_universal_ref) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) consteval { return true; },
        [](auto&&) consteval { return false; })(std::forward_like<Self>(arg));
    } else if constexpr (catchall_info::is_plain) {
      return make_overloads_no_validation<visitor_type>(
        [](f_arg_type) consteval { return true; },
        [](auto) consteval { return false; })(std::forward_like<Self>(arg));
    }
    static_assert("unreachable");
  }
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"

template <template <typename, typename> typename visitor_type,
          typename Self, typename... Fs>
constexpr overloads<visitor_type, Self, Fs...>::overloads(Fs... fs)
    : visitor_type<Self, Fs>{fs}... {
  if consteval {
    constexpr auto err = first_error<visitor_type<Self, Fs>::validate()...>();
    if constexpr (!err.ok()) {
      static_assert(false, err);
    }
    constexpr auto err2 = overload_validator<visitor_type, Self>::template validate<Fs...>();
    if constexpr (!err2.ok()) {
      static_assert(false, err2);
    }
  }
}
#pragma clang diagnostic pop
