#pragma once

#include "source/common/static_error.h"
#include "source/common/type_traits.h"

#include "source/extensions/filters/network/ssh/wire/internal/message_traits.h"

namespace wire::internal {

template <ssize_t I, ssize_t K>
consteval void check_sub_message_field_order(sub_message_index_t<I, K> idx) {
  // todo: validate that if a key field is present, the sub_message is also present
  if constexpr (idx.index != -1z) {
    static_assert(idx.key_field_index >= 0z && idx.key_field_index < idx.index,
                  "sub_message fields must be preceded by their corresponding key_field");
  }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"

template <typename Self, typename F>
struct oneof_validator {
  consteval static decltype(auto) validate() {
    using msg_type = callable_info_t<std::remove_reference_t<F>>::arg_type;
    if constexpr (!decltype(std::decay_t<Self>::message)::template has_option<msg_type>()) {
      return static_errorf<"argument type is not a possible message that could be visited: {}", type_name<msg_type>()>();
    } else {
      return no_error;
    }
  }
};
#pragma clang diagnostic pop

} // namespace wire::internal