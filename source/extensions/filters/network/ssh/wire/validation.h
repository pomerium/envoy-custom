#pragma once

#include "source/common/visit.h"
#include <cstdio>
#include <type_traits>

#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"

namespace wire::tags {
struct no_validation : ::tags::no_validation {
  // these methods are intentionally left undefined; no_validation implements Encoder and Decoder,
  // but any code paths that would call no_validation::encode/decode must not be reachable.
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance&) const noexcept;
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance&, size_t) noexcept;
};

static_assert(is_tag_no_validation<no_validation>);
} // namespace wire::tags

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
    static constexpr auto list = {std::is_same_v<typename T::key_field_type, Args>...};
    constexpr auto it = std::find(list.begin(), list.end(), true);
    return it == list.end() ? -1 : std::distance(list.begin(), it);
  }
  return -1;
}

template <typename... Args>
consteval auto sub_message_index() {
  static constexpr std::array<bool, sizeof...(Args)> list = {is_sub_message<Args>::value...};
  static constexpr std::array<ssize_t, sizeof...(Args)> key_list = {key_field_index<Args, Args...>()...};
  static_assert(list.size() == key_list.size());
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
consteval void check_sub_message_field_order() {
  if constexpr (auto idx = sub_message_index<std::decay_t<Args>...>(); idx.index != -1z) {
    static_assert(idx.key_field_index >= 0z && idx.key_field_index < idx.index,
                  "sub_message arguments must be preceded by their corresponding key_field");
  }
}

} // namespace wire::detail