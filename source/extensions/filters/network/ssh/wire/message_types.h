#pragma once

#include "source/common/type_traits.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/internal/message_impl.h"
#include "source/extensions/filters/network/ssh/wire/internal/top_level_visitor.h"

namespace wire {

template <SshMessageType MT>
struct Msg : internal::MsgImplDefaults {
  static constexpr SshMessageType type = MT;
  static constexpr SshMessageType msg_type() { return MT; };
  using submsg_group = internal::TopLevelMessageGroup;
  static constexpr SshMessageType submsg_key = MT;
  static constexpr EncodingOptions submsg_key_encoding = None;
};

template <SshMessageType MT, static_string Key, EncodingOptions KeyOpts = LengthPrefixed>
struct SubMsg : internal::MsgImplDefaults {
  using submsg_group = internal::SubMsgGroup<MT>;
  static constexpr std::string_view submsg_key = Key;
  static constexpr EncodingOptions submsg_key_encoding = KeyOpts;
};

template <typename TopLevel>
struct BasicMessage final {
  TopLevel message;

  BasicMessage() = default;

  template <typename Subset>
    requires strict_subset_v<typename TopLevel::option_types, typename Subset::option_types>
  constexpr BasicMessage(BasicMessage<Subset>&& other)
      : message(std::move(other.message)) {}

  // This constructor is explicit when 'msg' is an lvalue reference to avoid unexpected copying
  // and/or forgetting std::move in places where a function accepts Message&& (common throughout).
  // For example, given the function 'dispatch(Message&&)':
  //  wire::DebugMsg d;
  //  dispatch(d);            // incorrect: this makes a copy, but it is not obvious
  //  dispatch(std::move(d)); // correct: moves 'd' into reset()
  //  dispatch(auto(d));      // correct: makes a copy of DebugMsg, then moves the copy into reset().
  // The conditional explicit specifier turns the incorrect case into a compiler error.
  template <typename T>
    requires (!std::same_as<std::decay_t<T>, BasicMessage>)
  constexpr explicit(std::is_lvalue_reference_v<T>) BasicMessage(T&& msg) {
    reset(std::forward<T>(msg));
  }

  template <typename T>
  constexpr BasicMessage& operator=(T&& msg) {
    reset(std::forward<T>(msg));
    return *this;
  }

  template <typename T>
  constexpr void reset(T&& msg) {
    message.reset(std::forward<T>(msg));
  }

  constexpr void reset() {
    message = TopLevel{};
  }

  constexpr bool has_value() const {
    return message.oneof.has_value();
  }

  constexpr SshMessageType msg_type() const { return *message.key_field(); }

  template <typename Self>
  [[nodiscard]] constexpr decltype(auto) visit(this Self&& self, auto... args) {
    if (self.message.oneof.has_value()) {
      return std::visit(make_overloads<internal::top_level_visitor, Self&&>(args...), *std::forward<Self>(self).message.oneof);
    }
    using return_type = decltype(std::visit(make_overloads<internal::top_level_visitor, Self&&>(args...), *std::forward<Self>(self).message.oneof));
    if constexpr (!std::is_void_v<return_type>) {
      return return_type{};
    }
  }

  constexpr auto operator<=>(const BasicMessage&) const = default;
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    if (payload_size == 0) {
      return 0;
    }
    message.key_field() = buffer.peekInt<SshMessageType>();
    return message.decode(buffer, payload_size);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    // NB: messages encode/decode their own types
    return message.encode(buffer);
  }
};

} // namespace wire