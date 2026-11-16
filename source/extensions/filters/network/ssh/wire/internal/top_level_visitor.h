#pragma once

#include "source/common/visit.h"

#include "source/extensions/filters/network/ssh/wire/internal/validation.h"

namespace wire::internal {

template <typename Self, typename F>
struct top_level_visitor : basic_visitor<Self, F> {
  using basic_visitor<Self, F>::is_catchall_visitor;
  using basic_visitor<Self, F>::arg_type_transform;

  static consteval decltype(auto) validate() {
    constexpr auto err = basic_visitor<Self, F>::validate();
    if constexpr (!err.ok()) {
      return err;
    } else if constexpr (!is_catchall_visitor) {
      return oneof_validator<Self, F>::validate();
    } else {
      return no_error;
    }
  }
  using basic_visitor<Self, F>::operator();
};

} // namespace wire::internal