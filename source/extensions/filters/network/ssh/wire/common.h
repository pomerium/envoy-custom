#pragma once

#include <cstdint>
#include <limits>
#include <type_traits>
#include <utility>
#include <vector>
#include <string>

#include "fmt/format.h"
#include "magic_enum/magic_enum.hpp"

namespace wire {

// Top level SSH message types
enum class SshMessageType : uint8_t {
  Invalid = 0,
  // Transport layer protocol
  Disconnect = 1,     // https://datatracker.ietf.org/doc/html/rfc4253#section-11.1
  Ignore = 2,         // https://datatracker.ietf.org/doc/html/rfc4253#section-11.2
  Unimplemented = 3,  // https://datatracker.ietf.org/doc/html/rfc4253#section-11.4
  Debug = 4,          // https://datatracker.ietf.org/doc/html/rfc4253#section-11.3
  ServiceRequest = 5, // https://datatracker.ietf.org/doc/html/rfc4253#section-10
  ServiceAccept = 6,  // https://datatracker.ietf.org/doc/html/rfc4253#section-10
  ExtInfo = 7,        // https://datatracker.ietf.org/doc/html/rfc8308#section-2.3
  KexInit = 20,       // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
  NewKeys = 21,       // https://datatracker.ietf.org/doc/html/rfc4253#section-7.3
  KexDHInit = 30,     // https://datatracker.ietf.org/doc/html/rfc4253#section-8
  KexDHReply = 31,    // https://datatracker.ietf.org/doc/html/rfc4253#section-8
  KexECDHInit = 30,   // https://datatracker.ietf.org/doc/html/rfc5656#section-4
  KexECDHReply = 31,  // https://datatracker.ietf.org/doc/html/rfc5656#section-4

  // User authentication protocol
  UserAuthRequest = 50,      // https://datatracker.ietf.org/doc/html/rfc4252#section-5
  UserAuthFailure = 51,      // https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
  UserAuthSuccess = 52,      // https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
  UserAuthBanner = 53,       // https://datatracker.ietf.org/doc/html/rfc4252#section-5.4
  UserAuthPubKeyOk = 60,     // https://datatracker.ietf.org/doc/html/rfc4252#section-7
  UserAuthInfoRequest = 60,  // https://datatracker.ietf.org/doc/html/rfc4256#section-3.2
  UserAuthInfoResponse = 61, // https://datatracker.ietf.org/doc/html/rfc4256#section-3.2

  // Connection protocol
  GlobalRequest = 80,           // https://datatracker.ietf.org/doc/html/rfc4254#section-4
  RequestSuccess = 81,          // https://datatracker.ietf.org/doc/html/rfc4254#section-4
  RequestFailure = 82,          // https://datatracker.ietf.org/doc/html/rfc4254#section-4
  ChannelOpen = 90,             // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
  ChannelOpenConfirmation = 91, // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
  ChannelOpenFailure = 92,      // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
  ChannelWindowAdjust = 93,     // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
  ChannelData = 94,             // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
  ChannelExtendedData = 95,     // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
  ChannelEOF = 96,              // https://datatracker.ietf.org/doc/html/rfc4254#section-5.3
  ChannelClose = 97,            // https://datatracker.ietf.org/doc/html/rfc4254#section-5.3
  ChannelRequest = 98,          // https://datatracker.ietf.org/doc/html/rfc4254#section-5.4
  ChannelSuccess = 99,          // https://datatracker.ietf.org/doc/html/rfc4254#section-5.4
  ChannelFailure = 100,         // https://datatracker.ietf.org/doc/html/rfc4254#section-5.4

  // Extensions
  // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL

  // OpenSSH ping extension
  Ping = 192,
  Pong = 193,
};

constexpr inline SshMessageType operator~(SshMessageType t) {
  return static_cast<SshMessageType>(~std::to_underlying(t));
}

// This is required to use SshMessageType with Envoy buffer operations
constexpr inline SshMessageType operator|(SshMessageType l, SshMessageType r) {
  return static_cast<SshMessageType>(std::to_underlying(l) | std::to_underlying(r));
}

constexpr uint32_t MaxPacketSize = 256 * 1024;
constexpr uint32_t MinPacketSize = 4 + 1;
constexpr uint32_t ChannelMaxPacketSize = 1 << 15;
constexpr uint32_t ChannelWindowSize = 64 * ChannelMaxPacketSize;

// List of allowed integer types that can be used in SSH messages.
// See RFC4251 § 5
//
// This is effectively:
//  interface SshIntegerType {
//    ~uint8 | ~uint32 | ~uint64_t
//  }
template <typename T>
concept SshIntegerType =
  std::same_as<T, uint8_t> ||
  std::same_as<T, uint32_t> ||
  std::same_as<T, uint64_t> ||
  std::same_as<T, SshMessageType>;

// List of allowed string types that can be used in SSH messages.
// std::vector<uint8_t> is aliased by the name 'bytes', not used here to prevent circular import
template <typename T>
concept SshStringType =
  std::same_as<T, std::string> ||
  std::same_as<T, std::vector<uint8_t>>;

} // namespace wire

namespace magic_enum::customize {
template <>
struct enum_range<wire::SshMessageType> {
  static constexpr int min = std::numeric_limits<std::underlying_type_t<wire::SshMessageType>>::min();
  static constexpr int max = std::numeric_limits<std::underlying_type_t<wire::SshMessageType>>::max();
};
} // namespace magic_enum::customize

namespace wire {
// specialization of format_as for SshMessageType, used for fmt::format
inline constexpr auto format_as(SshMessageType mt) {
  if (magic_enum::enum_contains(mt)) {
    return fmt::format("{} ({})", magic_enum::enum_name(mt), std::to_underlying(mt));
  }
  return fmt::format("{}", std::to_underlying(mt));
}
} // namespace wire
