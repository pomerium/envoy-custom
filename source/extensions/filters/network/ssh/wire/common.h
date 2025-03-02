#pragma once

#include "fmt/format.h"

namespace wire {

enum class SshMessageType : uint8_t {
  Invalid = 0,
  // Transport layer protocol
  Disconnect = 1,
  Ignore = 2,
  Unimplemented = 3,
  Debug = 4,
  ServiceRequest = 5,
  ServiceAccept = 6,
  ExtInfo = 7,
  KexInit = 20,
  NewKeys = 21,
  KexDHInit = 30,
  KexDHReply = 31,
  KexECDHInit = 30,
  KexECDHReply = 31,
  KexDHGexGroup = 31,
  KexDHGexInit = 32,
  KexDHGexReply = 33,
  KexDHGexRequest = 34,

  // User authentication protocol
  UserAuthRequest = 50,
  UserAuthFailure = 51,
  UserAuthSuccess = 52,
  UserAuthBanner = 53,
  UserAuthPubKeyOk = 60,
  UserAuthPasswdChangeReq = 60,
  UserAuthInfoRequest = 60,
  UserAuthGSSAPIResponse = 60,
  UserAuthInfoResponse = 61,
  UserAuthGSSAPIToken = 61,
  UserAuthGSSAPIExchangeComplete = 63,
  UserAuthGSSAPIError = 64,
  UserAuthGSSAPIErrTok = 65,
  UserAuthGSSAPIMIC = 66,

  // Connection protocol
  GlobalRequest = 80,
  RequestSuccess = 81,
  RequestFailure = 82,
  ChannelOpen = 90,
  ChannelOpenConfirmation = 91,
  ChannelOpenFailure = 92,
  ChannelWindowAdjust = 93,
  ChannelData = 94,
  ChannelExtendedData = 95,
  ChannelEOF = 96,
  ChannelClose = 97,
  ChannelRequest = 98,
  ChannelSuccess = 99,
  ChannelFailure = 100,
};

inline constexpr auto format_as(SshMessageType mt) {
  return fmt::underlying(mt);
}

constexpr inline SshMessageType operator~(SshMessageType t) {
  return static_cast<SshMessageType>(~static_cast<uint8_t>(t));
}
constexpr inline SshMessageType operator|(SshMessageType l, SshMessageType r) {
  return static_cast<SshMessageType>(static_cast<uint8_t>(l) | static_cast<uint8_t>(r));
}

// List of allowed integer types that can be used in SSH messages.
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
