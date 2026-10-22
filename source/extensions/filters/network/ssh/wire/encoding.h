#pragma once

#include "source/common/concepts.h"

#include <concepts>
#include <cstddef>
#include <string>
#include <utility>

#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/buffer_io.h"
#include "source/extensions/filters/network/ssh/wire/key_field.h"
#include "source/extensions/filters/network/ssh/wire/internal/validation.h"

namespace wire {

template <typename T>
concept Encoder = requires(T t) {
  // looks like: absl::StatusOr<size_t> encode(Envoy::Buffer::Instance&) const noexcept
  { t.encode(std::declval<Envoy::Buffer::Instance&>()) } noexcept -> std::same_as<absl::StatusOr<size_t>>;
};

template <typename T>
concept Decoder = requires(T t) {
  // looks like: absl::StatusOr<size_t> decode(Envoy::Buffer::Instance&, size_t) noexcept
  { t.decode(std::declval<Envoy::Buffer::Instance&>(), size_t{}) } noexcept -> std::same_as<absl::StatusOr<size_t>>;
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++26-extensions"

// Utility function to decode a list of Decoder objects in order. The size passed to each Decoder's
// decode method will be adjusted after each is read. Returns the total number of bytes read.
template <typename... Args>
  requires (sizeof...(Args) > 0)
absl::StatusOr<size_t> decodeSequence(Envoy::Buffer::Instance& buffer, explicit_size_t auto limit, Args&&... args) noexcept {
  static constinit auto subMsgIndex = internal::sub_message_index<Args...>();
  internal::check_sub_message_field_order(subMsgIndex);

  if (buffer.length() < limit) {
    return absl::InvalidArgumentError("short read");
  }
  size_t n = 0;
  absl::Status stat{};

  auto decodeOne = [&](this auto&& decode_one, auto&& field) -> bool {
    if constexpr (is_key_field_v<std::decay_t<decltype(field)>>) {
      if constexpr (subMsgIndex.index != -1) {
        return decode_one(args...[subMsgIndex.index].key_field());
      } else {
        static_assert(false, "key field exists but corresponding sub_message is missing");
      }
    } else {
      // NB: (limit-n) is allowed to be zero here
      auto r = field.decode(buffer, limit - n);
      if (!r.ok()) {
        stat = r.status();
        return false;
      }
      ASSERT(*r <= limit - n, "decode() returned value >= limit");
      n += *r;
      return true;
    }
  };

  // This fold expression calls decodeOne for each field, and stops if decodeOne returns false.
  (void)(decodeOne(std::forward<Args>(args)) && ...);

  // stat and n are updated from within decodeOne
  if (!stat.ok()) {
    return stat;
  }
  return n;
}

inline absl::StatusOr<size_t> decodeSequence(Envoy::Buffer::Instance&, explicit_size_t auto) {
  return 0;
}

// Utility function to encode a list of Encoder objects in order. Returns the total number of bytes
// written.
template <typename... Args>
  requires (sizeof...(Args) > 0)
absl::StatusOr<size_t> encodeSequence(Envoy::Buffer::Instance& buffer, const Args&... args) noexcept {
  static constinit auto subMsgIndex = internal::sub_message_index<Args...>();
  internal::check_sub_message_field_order(subMsgIndex);

  size_t n = 0;
  absl::Status stat{};

  auto encodeOne = [&](this auto&& encode_one, auto& field) -> bool {
    if constexpr (is_key_field_v<std::decay_t<decltype(field)>>) {
      if constexpr (subMsgIndex.index != -1) {
        return encode_one(args...[subMsgIndex.index].key_field());
      } else {
        static_assert(false, "key field exists but corresponding sub_message is missing");
      }
    } else {
      auto r = field.encode(buffer);
      if (!r.ok()) [[unlikely]] {
        stat = r.status();
        return false;
      }
      n += *r;
      if (n < MaxPacketSize) [[likely]] {
        return true;
      } else {
        stat = absl::AbortedError("message size too large");
        return false;
      }
    }
  };

  // This fold expression calls encodeOne for each field, and stops if encodeOne returns false.
  (void)(encodeOne(args) && ...);

  // stat and n are updated from within encodeOne
  if (!stat.ok()) {
    return stat;
  }
  return n;
}

#pragma clang diagnostic pop

inline absl::StatusOr<size_t> encodeSequence(Envoy::Buffer::Instance&) {
  return 0;
}

// Utility function to decode a message, including a message type and a list of fields. The decoded
// message type is validated to ensure it matches the expected type. Returns the total number of
// bytes read (including the message type byte).
template <typename... Fields>
absl::StatusOr<size_t> decodeMsg(Envoy::Buffer::Instance& buffer, SshMessageType msg_type, explicit_size_t auto limit, Fields&&... fields) noexcept {
  if (limit == 0) {
    return 0;
  }
  if (buffer.length() < limit) {
    return absl::InvalidArgumentError("short read");
  }
  if (auto mt = buffer.drainInt<SshMessageType>(); mt != msg_type) {
    return absl::InvalidArgumentError(
      fmt::format("decoded unexpected message type {}, expected {}", mt, msg_type));
  }
  auto n = decodeSequence(buffer, limit - 1, std::forward<Fields>(fields)...);
  if (n.ok()) {
    return 1 + *n;
  }
  return n;
}

// Utility function to encode a message, including a message type and a list of fields. Returns
// the total number of bytes written (including the message type byte).
template <typename... Fields>
absl::StatusOr<size_t> encodeMsg(Envoy::Buffer::Instance& buffer, SshMessageType msg_type, const Fields&... fields) noexcept {
  buffer.writeByte(msg_type);
  auto n = encodeSequence(buffer, fields...);
  if (n.ok()) {
    return 1 + *n;
  }
  return n;
}

} // namespace wire
