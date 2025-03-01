#pragma once

#include <type_traits>

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

template <SshMessageType T>
struct is_channel_msg : std::false_type {};

template <SshMessageType T>
inline constexpr bool is_channel_msg_v = is_channel_msg<T>::value;

template <> struct is_channel_msg<SshMessageType::ChannelRequest> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelOpenConfirmation> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelOpenFailure> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelWindowAdjust> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelData> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelExtendedData> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelEOF> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelClose> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelSuccess> : std::true_type {};
template <> struct is_channel_msg<SshMessageType::ChannelFailure> : std::true_type {};

inline constexpr auto format_as(SshMessageType mt) {
  return fmt::underlying(mt);
}

constexpr inline SshMessageType operator~(SshMessageType t) {
  return static_cast<SshMessageType>(~static_cast<uint8_t>(t));
}
constexpr inline SshMessageType operator|(SshMessageType l, SshMessageType r) {
  return static_cast<SshMessageType>(static_cast<uint8_t>(l) | static_cast<uint8_t>(r));
}

// type_or_value_type<T> is equivalent to T, unless T is a vector<U>, in which case it will be
// equivalent to U. This is used to check that for some field<T>, T can be encoded/decoded; but
// lists are handled in a generic way, so we only need to check that the contents of the list
// can be encoded/decoded, not that specific list.
template <typename T>
struct type_or_value_type : std::type_identity<T> {};

template <typename T, typename Allocator>
struct type_or_value_type<std::vector<T, Allocator>> : std::type_identity<T> {};

template <typename T>
using type_or_value_type_t = type_or_value_type<T>::type;

// is_vector<T> is true if T is a vector of any type, otherwise false. This is used to enable
// decoding logic for fields of list types.
template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

// all_values_equal is true if every value in Actual is equal to Expected, otherwise false.
template <auto Expected, auto... Actual>
constexpr bool all_values_equal = ((Expected == Actual) && ...);

// values_unique returns true if there are no duplicates in the list, otherwise false.
constexpr bool values_unique(std::initializer_list<std::string_view> arr) {
  for (size_t i = 0; i < arr.size(); ++i) {
    for (size_t j = i + 1; j < arr.size(); ++j) {
      if (*(arr.begin() + i) == *(arr.begin() + j)) {
        return false;
      }
    }
  }
  return true;
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
