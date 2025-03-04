#pragma once

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/util.h"

namespace wire::detail {

template <SshMessageType MT>
struct OverloadGroup {};

template <SshMessageType MT>
struct SubMsgGroup {};

enum class TopLevelMessageGroup {};

template <typename T>
struct overload_for : std::type_identity<T> {};

template <typename T>
using overload_for_t = typename overload_for<std::remove_cv_t<T>>::type;

template <typename T>
constexpr bool is_overload = !std::is_same_v<std::remove_cv_t<T>, overload_for_t<T>>;

template <typename T>
struct visitor_info {
  using arg_type = void;
};

template <typename T>
struct remove_optref : std::type_identity<T> {};

template <typename T>
struct remove_optref<Envoy::OptRef<T>> : std::type_identity<T> {};

template <typename T>
using remove_optref_t = remove_optref<T>::type;

template <typename R, typename T, typename Arg>
struct visitor_info<R (T::*)(Arg) const> {
  using return_type = R;
  using arg_type = std::remove_cv_t<remove_optref_t<std::decay_t<Arg>>>;
  using arg_type_with_cv = remove_optref_t<std::decay_t<Arg>>;
  using arg_type_with_cv_optref = std::decay_t<Arg>;
};

template <typename F>
using visitor_info_t = visitor_info<decltype(&std::decay_t<F>::operator())>;

template <typename F>
using visitor_arg_type_t = visitor_info_t<F>::arg_type;

template <typename F>
struct single_visitor : F {
  static constexpr bool selected_overload = false;
  using F::operator();
};

template <typename F>
  requires is_overload<visitor_arg_type_t<F>>
struct single_visitor<F> : private F {
  single_visitor(F f)
      : F(f) {};

  static_assert(std::is_same_v<typename visitor_info_t<F>::arg_type_with_cv_optref,
                               Envoy::OptRef<typename visitor_info_t<F>::arg_type_with_cv>>,
                "overloaded messages must be visited as Envoy::OptRef<T> or Envoy::OptRef<const T>");
  static constexpr bool selected_overload = true;
  using arg = visitor_arg_type_t<F>;
  using overload = overload_for_t<arg>;

  decltype(auto) operator()(const overload& o) const {
    return F::operator()(const_cast<overload&>(o).template resolve<arg>());
  }
  decltype(auto) operator()(overload& o) const {
    return F::operator()(o.template resolve<arg>());
  }
};

template <typename... Fs>
struct top_level_message_visitor : single_visitor<Fs>... {
  top_level_message_visitor(Fs... ts)
      : single_visitor<Fs>{ts}... {};
  using single_visitor<Fs>::operator()...;
};

} // namespace wire::detail