#pragma once

#include "source/common/type_traits.h"
#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace wire::detail {

// overloaded messages
template <SshMessageType MT>
struct OverloadGroup {};

// specializations of overload_set_for are defined in messages.h
template <DecayedType T>
struct overload_set_for : std::type_identity<T> {};

template <DecayedType T>
using overload_set_for_t = typename overload_set_for<T>::type;

template <DecayedType T>
constexpr bool is_overloaded_message = !std::is_same_v<T, overload_set_for_t<T>>;

template <bool IsConst, typename F>
struct opt_ref_validator {
  consteval static bool validate() {
    using info_t = callable_info_t<std::remove_reference_t<F>>;
    return std::is_same_v<typename info_t::raw_arg_type,
                          opt_ref<typename info_t::arg_type_with_cv>>;
  }
};

// specializations of is_overloaded_message are defined in messages.h
template <DecayedType T>
struct is_overload_set : std::false_type {};

template <DecayedType T>
constexpr bool is_overload_set_v = is_overload_set<T>::value;

// sub-messages
template <SshMessageType MT>
struct SubMsgGroup {};

// top level messages
enum class TopLevelMessageGroup {};

// specializations of is_top_level_message are defined in messages.h
template <DecayedType T>
struct is_top_level_message : std::false_type {};

template <DecayedType T>
constexpr bool is_top_level_message_v = is_top_level_message<T>::value;

template <typename T>
concept TopLevelMessage = is_top_level_message_v<T>;

template <bool IsConst, typename F>
struct top_level_visitor : F {
  static constexpr bool is_catchall_visitor = true;
  template <typename T>
  using arg_type_transform = T;

  static consteval void validate() {}
  using F::operator();
};

template <bool IsConst, typename F>
  requires TopLevelMessage<callable_arg_type_t<F>>
struct top_level_visitor<IsConst, F> : F {
  constexpr top_level_visitor(F f)
      : F(f) {}
  static constexpr bool is_catchall_visitor = false;
  template <typename T>
  using arg_type_transform = T;

  static consteval void validate() {
    if constexpr (!const_validator<IsConst, F>::validate()) {
      static_assert(false,
                    "visited message is const-qualified, but handler has non-const argument type");
    }
  }

  using F::operator();
};

template <bool IsConst, typename F>
  requires TopLevelMessage<callable_arg_type_t<F>> && is_overloaded_message<callable_arg_type_t<F>>
struct top_level_visitor<IsConst, F> : private F {
  constexpr top_level_visitor(F f)
      : F(f) {}
  static constexpr bool is_catchall_visitor = false;
  template <typename T>
  using arg_type_transform = overload_set_for_t<T>;

  static consteval void validate() {
    if constexpr (!const_validator<IsConst, F>::validate()) {
      static_assert(false, "visited message is const-qualified, but handler has non-const argument type");
    }
    if constexpr (!opt_ref_validator<IsConst, F>::validate()) {
      static_assert(false, "overloaded messages must be visited as `opt_ref<T>` or `opt_ref<const T>` (by value)");
    }
  }

  using arg = callable_arg_type_t<F>;
  decltype(auto) operator()(arg_type_transform<arg> o) const {
    return F::operator()(o.template resolve<arg>());
  }
};

} // namespace wire::detail