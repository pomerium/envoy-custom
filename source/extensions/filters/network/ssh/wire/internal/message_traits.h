#pragma once

#include "source/extensions/filters/network/ssh/wire/key_field.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/optional_field.h"
#include <algorithm>

namespace wire::internal {

template <ssize_t I, ssize_t K>
struct sub_message_index_t {
  static constexpr ssize_t index = I;
  static constexpr ssize_t key_field_index = K;
};

template <typename T, typename... Args>
consteval ssize_t key_field_index() {
  if constexpr (is_sub_message<T>::value) {
    static constexpr auto list = {std::is_same_v<key_field<T>, Args>...};
    constexpr auto it = std::find(list.begin(), list.end(), true);
    return it == list.end() ? -1 : std::distance(list.begin(), it);
  }
  return -1;
}

template <typename... Args>
consteval auto sub_message_index() {
  static constexpr std::array<bool, sizeof...(Args)> list = {is_sub_message<std::decay_t<Args>>::value...};
  static constexpr std::array<ssize_t, sizeof...(Args)> key_list = {key_field_index<std::decay_t<Args>, std::decay_t<Args>...>()...};
  static_assert(list.size() == key_list.size());
  static_assert(std::count(list.begin(), list.end(), true) <= 1, "messages can only have one sub_message field");
  static constexpr auto submsg_pos = std::find(list.begin(), list.end(), true);
  if constexpr (submsg_pos == list.end()) {
    return sub_message_index_t<-1, -1>{};
  } else {
    static constexpr ssize_t index = std::distance(list.begin(), submsg_pos);
    static constexpr ssize_t key_entry = key_list.at(index);
    return sub_message_index_t<index, key_entry>{};
  }
}

template <typename... Args>
consteval ssize_t selector_field_index() {
  static constexpr std::array<bool, sizeof...(Args)> list = {is_selector_field_v<std::decay_t<Args>>...};
  static constexpr std::array<bool, sizeof...(Args)> opt_list = {is_optional_field_v<std::decay_t<Args>>...};
  static_assert(std::count(list.begin(), list.end(), true) <= 1, "messages can only have one optional_flags_field field");
  static constexpr auto flags_field_pos = std::find(list.begin(), list.end(), true);
  if constexpr (flags_field_pos == list.end()) {
    return -1;
  } else {
    static constexpr auto first_opt_field = std::find(opt_list.begin(), opt_list.end(), true);
    // Note: it is valid to encode a selector field without also encoding any optional fields
    if constexpr (first_opt_field != opt_list.end()) {
      static_assert(std::distance(list.begin(), flags_field_pos) < std::distance(opt_list.begin(), first_opt_field),
                    "optional flags field must be ordered before any optional fields in the message");
    }
    return std::distance(list.begin(), flags_field_pos);
  }
}

} // namespace wire::internal