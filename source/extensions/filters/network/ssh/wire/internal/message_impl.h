#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/internal/message_groups.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"

namespace wire::internal {

template <typename T>
concept has_override_encode = std::is_same_v<decltype(&T::encode), absl::StatusOr<size_t> (T::*)(Envoy::Buffer::Instance&) const noexcept>;

template <typename T>
concept has_override_decode = std::is_same_v<decltype(&T::decode), absl::StatusOr<size_t> (T::*)(Envoy::Buffer::Instance&, size_t) noexcept>;

template <typename T>
concept has_override_operator_eq = std::is_same_v<decltype(&T::operator==), bool (T::*)(const T&) const>;

template <typename T>
concept has_override_operator_ne = std::is_same_v<decltype(&T::operator!=), bool (T::*)(const T&) const>;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"

template <typename T>
consteval bool has_unkeyed_sub_message() {
  const auto& [... fields] = T{};
  constexpr auto subMsgIndex = sub_message_index<decltype(fields)...>();
  if constexpr (subMsgIndex.index == -1) {
    return false;
  } else {
    return decltype(fields...[subMsgIndex.index])::key_encoding == EncodingOptions::Omit;
  }
}

struct MsgImplDefaults {
  template <typename T>
    requires is_msg<T> && (!has_override_decode<T>)
  absl::StatusOr<size_t> decode(this T& self, Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    auto& [... fields] = self;
    return decodeMsg(buffer, self.msg_type(), payload_size, fields...);
  }

  template <typename T>
    requires is_msg<T> && (!has_override_encode<T>)
  absl::StatusOr<size_t> encode(this T const& self, Envoy::Buffer::Instance& buffer) noexcept {
    const auto& [... fields] = self;
    return encodeMsg(buffer, self.msg_type(), fields...);
  }

  template <typename T>
    requires is_sub_msg<T> && (!has_override_decode<T>)
  absl::StatusOr<size_t> decode(this T& self, Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    auto& [... fields] = self;
    return decodeSequence(buffer, payload_size, fields...);
  }

  template <typename T>
    requires is_sub_msg<T> && (!has_override_encode<T>)
  absl::StatusOr<size_t> encode(this T const& self, Envoy::Buffer::Instance& buffer) noexcept {
    const auto& [... fields] = self;
    return encodeSequence(buffer, fields...);
  }

  template <typename T>
    requires (is_msg<T> || is_sub_msg<T>) && (!has_override_operator_eq<T>)
  constexpr bool operator==(this T const& self, const T& other) {
    const auto& [... selfFields] = self;
    const auto& [... otherFields] = other;
    static_assert(sizeof...(selfFields) == sizeof...(otherFields));
    // TODO: in c++26 mode, index sequences can be destructured
    // (see https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2025/p1789r3.pdf section 2)
    // Note: clang already implements this, but it is not available with -std=c++23
    return [&]<size_t... I>(std::index_sequence<I...>) {
      static_assert(sizeof...(I) == sizeof...(selfFields));
      return ((selfFields...[I] == otherFields...[I]) && ...);
    }(std::make_index_sequence<sizeof...(selfFields)>());
  }

  template <typename T>
    requires (is_msg<T> || is_sub_msg<T>) && (!has_override_operator_ne<T>)
  constexpr bool operator!=(this T const& self, const T& other) {
    return !(self == other);
  }

  template <typename Msg, typename Self>
    requires (has_unkeyed_sub_message<Self>())
  absl::StatusOr<Msg&> resolve(this Self& self) {
    auto& [... fields] = self;
    constexpr auto subMsgIndex = sub_message_index<decltype(fields)...>();

    using key_type = decltype(fields...[subMsgIndex.index])::key_type;
    auto& subMsg = fields...[subMsgIndex.index];
    if (subMsg.template holds_alternative<Msg>()) {
      return subMsg.template get<Msg>();
    }
    static_assert(subMsg.template has_option<Msg>());
    subMsg.key_field() = key_type{Msg::submsg_key};
    if (auto stat = subMsg.decodeUnknown().status(); !stat.ok()) {
      return stat;
    }
    ASSERT(subMsg.template holds_alternative<Msg>());
    return subMsg.template get<Msg>();
  }

  template <typename Msg, typename Self>
    requires (!has_unkeyed_sub_message<Self>())
  absl::StatusOr<Msg&> resolve(this Self& self) = delete;
};

#pragma clang diagnostic pop

} // namespace wire::internal
