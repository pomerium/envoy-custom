#pragma once

#include <algorithm>
#include <cstdio>
#include <type_traits>

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace wire::detail {

template <typename T>
struct is_sub_message : std::false_type {};

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

template <ssize_t I, ssize_t K>
consteval void check_sub_message_field_order(sub_message_index_t<I, K> idx) {
  // todo: validate that if a key field is present, the sub_message is also present
  if constexpr (idx.index != -1z) {
    static_assert(idx.key_field_index >= 0z && idx.key_field_index < idx.index,
                  "sub_message fields must be preceded by their corresponding key_field");
  }
}

} // namespace wire::detail