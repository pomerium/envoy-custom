#pragma once

#include <cstdint>
#include <type_traits>
#include <string>
#include <utility>

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/message_traits.h"

namespace wire {

struct BaseSshMsg {
  virtual ~BaseSshMsg() = default;
  virtual SshMessageType msg_type() const PURE; // NOLINT

  virtual absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept PURE;
  virtual absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept PURE;
};

template <SshMessageType MT>
struct Msg : BaseSshMsg {
  constexpr static const SshMessageType type = MT;
  SshMessageType msg_type() const final { return MT; };
  using submsg_group = detail::TopLevelMessageGroup;
  static constexpr SshMessageType submsg_key = MT;
  static constexpr EncodingOptions submsg_key_encoding = None;

  bool operator==(const Msg<MT>&) const {
    return true;
  }
};

template <SshMessageType MT, typename T, size_t Id>
struct OverloadMsg : T {
  using submsg_group = detail::OverloadGroup<MT>;
  static constexpr uint64_t submsg_key = Id; // NB: this must be uint64_t; size_t is not an allowed field type
  static constexpr EncodingOptions submsg_key_encoding = None;

  OverloadMsg() = default;

  OverloadMsg(T&& t)
      : T(std::move(t)) {};
  OverloadMsg(const T& t)
      : T(t) {};
};

// A ChannelMsg is any struct with a mutable field 'recipient_channel' of type field<uint32_t>,
// for example:
//  struct Foo {
//    mutable field<uint32_t> recipient_channel;
//  };
template <typename T>
concept ChannelMsg = requires(T t) {
  requires std::same_as<std::decay_t<decltype((t.recipient_channel))>, field<uint32_t>>;
  { std::as_const(t).recipient_channel = std::declval<field<uint32_t>>() };
};

template <typename... Ts>
struct OverloadedMessage : Msg<first_type_t<Ts...>::type> {
  static_assert(all_values_equal<Ts::type...>,
                "all overloaded messages must have the same type");
  using Msg<first_type_t<Ts...>::type>::type;
  template <typename T>
  using overload_opt_for = OverloadMsg<type, T, 1 + index_of_type<T, Ts...>::value>;
  using message_type = sub_message<overload_opt_for<Ts>...>;

private:
  message_type message_;

  template <typename T>
  static consteval bool has_overload() {
    return message_type::template has_option<overload_opt_for<T>>();
  }

public:
  OverloadedMessage() = default;

  template <typename T>
    requires (has_overload<std::decay_t<T>>())
  explicit OverloadedMessage(T&& msg) {
    message_.reset(overload_opt_for<std::decay_t<T>>{std::forward<T>(msg)});
  }

  template <typename T>
    requires (has_overload<T>())
  opt_ref<T> resolve() {
    constexpr auto index = index_of_type<T, Ts...>::value;
    if (*message_.key_field() == 0) {
      message_.key_field() = 1 + index;
      auto stat = message_.decodeUnknown();
      if (!stat.ok()) {
        return {};
      }
    }
    return message_.template get<index>();
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return message_.decode(buffer, payload_size);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return message_.encode(buffer);
  }
};

template <SshMessageType MT, fixed_string K>
struct SubMsg {
  virtual ~SubMsg() = default;
  using submsg_group = detail::SubMsgGroup<MT>;
  static constexpr std::string_view submsg_key = K.to_string();
  static constexpr EncodingOptions submsg_key_encoding = LengthPrefixed;

  virtual absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) PURE;
  virtual absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const PURE;
};

struct KexInitMessage : Msg<SshMessageType::KexInit> {
  field<fixed_bytes<16>> cookie;
  field<string_list, NameListFormat> kex_algorithms;
  field<string_list, NameListFormat> server_host_key_algorithms;
  field<string_list, NameListFormat> encryption_algorithms_client_to_server;
  field<string_list, NameListFormat> encryption_algorithms_server_to_client;
  field<string_list, NameListFormat> mac_algorithms_client_to_server;
  field<string_list, NameListFormat> mac_algorithms_server_to_client;
  field<string_list, NameListFormat> compression_algorithms_client_to_server;
  field<string_list, NameListFormat> compression_algorithms_server_to_client;
  field<string_list, NameListFormat> languages_client_to_server;
  field<string_list, NameListFormat> languages_server_to_client;
  field<bool> first_kex_packet_follows;
  field<uint32_t> reserved;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct KexEcdhInitMessage : Msg<SshMessageType::KexECDHInit> {
  field<bytes, LengthPrefixed> client_pub_key;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct KexEcdhReplyMsg : Msg<SshMessageType::KexECDHReply> {
  field<bytes, LengthPrefixed> host_key;
  field<bytes, LengthPrefixed> ephemeral_pub_key;
  field<bytes, LengthPrefixed> signature;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ServiceRequestMsg : Msg<SshMessageType::ServiceRequest> {
  field<std::string, LengthPrefixed> service_name;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ServiceAcceptMsg : Msg<SshMessageType::ServiceAccept> {
  field<std::string, LengthPrefixed> service_name;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

template <SshMessageType T>
struct EmptyMsg : Msg<T> {
  using Msg<T>::type;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type);
  }
};

struct ChannelOpenMsg : Msg<SshMessageType::ChannelOpen> {
  field<std::string, LengthPrefixed> channel_type;
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  field<bytes> extra;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct PtyReqChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest, "pty-req"> {
  field<std::string, LengthPrefixed> term_env;
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;
  field<std::string, LengthPrefixed> modes;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ShellChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest, "shell"> {
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    (void)buffer;
    (void)payload_size;
    return 0;
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    (void)buffer;
    return 0;
  }
};

struct WindowDimensionChangeChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest, "window-change"> {
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelRequestMsg : Msg<SshMessageType::ChannelRequest> {
  mutable field<uint32_t> recipient_channel;
  constexpr std::string& request_type() { return *request.key_field(); }
  field<bool> want_reply;
  sub_message<PtyReqChannelRequestMsg,
              ShellChannelRequestMsg,
              WindowDimensionChangeChannelRequestMsg>
    request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelOpenConfirmationMsg : Msg<SshMessageType::ChannelOpenConfirmation> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  field<bytes> extra;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelOpenFailureMsg : Msg<SshMessageType::ChannelOpenFailure> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelWindowAdjustMsg : Msg<SshMessageType::ChannelWindowAdjust> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> bytes_to_add;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelDataMsg : Msg<SshMessageType::ChannelData> {
  mutable field<uint32_t> recipient_channel;
  field<bytes, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelExtendedDataMsg : Msg<SshMessageType::ChannelExtendedData> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> data_type_code;
  field<bytes, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelEOFMsg : Msg<SshMessageType::ChannelEOF> {
  mutable field<uint32_t> recipient_channel;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelCloseMsg : Msg<SshMessageType::ChannelClose> {
  mutable field<uint32_t> recipient_channel;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelSuccessMsg : Msg<SshMessageType::ChannelSuccess> {
  mutable field<uint32_t> recipient_channel;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ChannelFailureMsg : Msg<SshMessageType::ChannelFailure> {
  mutable field<uint32_t> recipient_channel;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct HostKeysProveRequestMsg : SubMsg<SshMessageType::GlobalRequest, "hostkeys-prove-00@openssh.com"> {
  field<bytes_list, LengthPrefixed> hostkeys;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t len) override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct HostKeysMsg : SubMsg<SshMessageType::GlobalRequest, "hostkeys-00@openssh.com"> {
  field<bytes_list, LengthPrefixed> hostkeys;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t len) override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct GlobalRequestMsg : Msg<SshMessageType::GlobalRequest> {
  constexpr std::string& request_name() { return *request.key_field(); }
  field<bool> want_reply;
  sub_message<HostKeysProveRequestMsg, HostKeysMsg> request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct HostKeysProveResponseMsg : SubMsg<SshMessageType::RequestSuccess, "hostkeys-prove-00@openssh.com"> {
  field<bytes_list, LengthPrefixed> signatures;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t len) override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct GlobalRequestSuccessMsg : Msg<SshMessageType::RequestSuccess> {
  sub_message<HostKeysProveResponseMsg> response;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct GlobalRequestFailureMsg : EmptyMsg<SshMessageType::RequestFailure> {};

struct IgnoreMsg : Msg<SshMessageType::Ignore> {
  field<bytes, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct DebugMsg : Msg<SshMessageType::Debug> {
  field<bool> always_display;
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct UnimplementedMsg : Msg<SshMessageType::Unimplemented> {
  // FIXME: the sequence numbers in this message are likely going to be wrong, need to adjust them
  field<uint32_t> sequence_number;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct PubKeyUserAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest, "publickey"> {
  field<bool> has_signature;
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;
  field<bytes, LengthPrefixed> signature;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct KeyboardInteractiveUserAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest, "keyboard-interactive"> {
  field<std::string, LengthPrefixed> language_tag;
  field<string_list, NameListFormat> submethods;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct NoneAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest, "none"> {
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance&, size_t) override {
    return 0;
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance&) const override {
    return 0;
  }
};

struct UserAuthRequestMsg : Msg<SshMessageType::UserAuthRequest> {
  field<std::string, LengthPrefixed> username;
  field<std::string, LengthPrefixed> service_name;
  constexpr std::string& method_name() { return *request.key_field(); }
  sub_message<PubKeyUserAuthRequestMsg,
              KeyboardInteractiveUserAuthRequestMsg,
              NoneAuthRequestMsg>
    request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct UserAuthInfoPrompt {
  field<std::string, LengthPrefixed> prompt;
  field<bool> echo;
};

// implements Reader
size_t read(Envoy::Buffer::Instance& buffer, UserAuthInfoPrompt& prompt, size_t payload_size);

// implements Writer
size_t write(Envoy::Buffer::Instance& buffer, const UserAuthInfoPrompt& prompt);

struct UserAuthInfoRequestMsg : Msg<SshMessageType::UserAuthInfoRequest> {
  field<std::string, LengthPrefixed> name;
  field<std::string, LengthPrefixed> instruction;
  field<std::string, LengthPrefixed> language_tag;
  field<std::vector<UserAuthInfoPrompt>, ListSizePrefixed> prompts;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct UserAuthInfoResponseMsg : Msg<SshMessageType::UserAuthInfoResponse> {
  field<string_list, LengthPrefixed | ListSizePrefixed> responses;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct UserAuthBannerMsg : Msg<SshMessageType::UserAuthBanner> {
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct UserAuthFailureMsg : Msg<SshMessageType::UserAuthFailure> {
  field<string_list, NameListFormat> methods;
  field<bool> partial;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct DisconnectMsg : Msg<SshMessageType::Disconnect> {
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct UserAuthSuccessMsg : EmptyMsg<SshMessageType::UserAuthSuccess> {};
struct NewKeysMsg : EmptyMsg<SshMessageType::NewKeys> {};

struct UserAuthPubKeyOkMsg : Msg<SshMessageType::UserAuthPubKeyOk> {
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct ServerSigAlgsExtension : SubMsg<SshMessageType::ExtInfo, "server-sig-algs"> {
  field<string_list, NameListFormat> public_key_algorithms_accepted;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct PingExtension : SubMsg<SshMessageType::ExtInfo, "ping@openssh.com"> {
  field<std::string, LengthPrefixed> version;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct Extension {
  constexpr std::string& extension_name() { return *extension.key_field(); }
  sub_message<ServerSigAlgsExtension, PingExtension> extension;

  Extension() = default;
  template <typename T>
    requires (decltype(extension)::has_option<T>())
  explicit Extension(T&& ext) {
    extension.reset(std::forward<T>(ext));
  }
};

// implements Reader
size_t read(Envoy::Buffer::Instance& buffer, Extension& ext, size_t payload_size);

// implements Writer
size_t write(Envoy::Buffer::Instance& buffer, const Extension& ext);

struct ExtInfoMsg : Msg<SshMessageType::ExtInfo> {
  field<std::vector<Extension>, ListSizePrefixed> extensions;

  template <typename T>
  bool hasExtension() const {
    for (const auto& ext : *extensions) {
      if (ext.extension.holds_alternative<T>()) {
        return true;
      }
    }
    return false;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct PingMsg : Msg<SshMessageType::Ping> {
  field<std::string, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

struct PongMsg : Msg<SshMessageType::Pong> {
  field<std::string, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;
};

namespace detail {

using top_level_message = sub_message<
  DisconnectMsg,                                                  // 1
  IgnoreMsg,                                                      // 2
  UnimplementedMsg,                                               // 3
  DebugMsg,                                                       // 4
  ServiceRequestMsg,                                              // 5
  ServiceAcceptMsg,                                               // 6
  ExtInfoMsg,                                                     // 7
  KexInitMessage,                                                 // 20
  NewKeysMsg,                                                     // 21
  OverloadedMessage<KexEcdhInitMessage>,                          // 30 (2 overloads, 1 supported)
  OverloadedMessage<KexEcdhReplyMsg>,                             // 31 (3 overloads, 1 supported)
  UserAuthRequestMsg,                                             // 50
  UserAuthFailureMsg,                                             // 51
  UserAuthSuccessMsg,                                             // 52
  UserAuthBannerMsg,                                              // 53
  OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>, // 60 (4 overloads, 2 supported)
  OverloadedMessage<UserAuthInfoResponseMsg>,                     // 61 (2 overloads, 1 supported)
  GlobalRequestMsg,                                               // 80
  GlobalRequestSuccessMsg,                                        // 81
  GlobalRequestFailureMsg,                                        // 82
  ChannelOpenMsg,                                                 // 90
  ChannelOpenConfirmationMsg,                                     // 91
  ChannelOpenFailureMsg,                                          // 92
  ChannelWindowAdjustMsg,                                         // 93
  ChannelDataMsg,                                                 // 94
  ChannelExtendedDataMsg,                                         // 95
  ChannelEOFMsg,                                                  // 96
  ChannelCloseMsg,                                                // 97
  ChannelRequestMsg,                                              // 98
  ChannelSuccessMsg,                                              // 99
  ChannelFailureMsg,                                              // 100
  PingMsg,                                                        // 192
  PongMsg>;                                                       // 193

static_assert(std::is_copy_constructible_v<top_level_message>);
static_assert(std::is_copy_assignable_v<top_level_message>);
static_assert(std::is_move_constructible_v<top_level_message>);
static_assert(std::is_move_assignable_v<top_level_message>);

template <> struct overload_for<KexEcdhInitMessage> : std::type_identity<OverloadedMessage<KexEcdhInitMessage>> {};
template <> struct overload_for<KexEcdhReplyMsg> : std::type_identity<OverloadedMessage<KexEcdhReplyMsg>> {};
template <> struct overload_for<UserAuthPubKeyOkMsg> : std::type_identity<OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>> {};
template <> struct overload_for<UserAuthInfoRequestMsg> : std::type_identity<OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>> {};
template <> struct overload_for<UserAuthInfoResponseMsg> : std::type_identity<OverloadedMessage<UserAuthInfoResponseMsg>> {};

template <typename T>
struct is_top_level_message : std::false_type {};

template <typename T>
  requires (top_level_message::template has_option<overload_for_t<T>>())
struct is_top_level_message<T> : std::true_type {};

} // namespace detail

struct Message : BaseSshMsg {
  detail::top_level_message message;

  Message() = default;

  template <typename T>
    requires (!std::same_as<std::decay_t<T>, Message>)
  Message(T&& msg) {
    reset(std::forward<T>(msg));
  }

  template <typename T>
  Message& operator=(T&& msg) {
    reset(std::forward<T>(msg));
    return *this;
  }

  template <typename T>
  void reset(T&& msg) {
    if constexpr (!std::is_same_v<std::decay_t<T>, detail::overload_for_t<std::decay_t<T>>>) {
      message.reset(detail::overload_for_t<std::decay_t<T>>{std::forward<T>(msg)});
    } else {
      message.reset(std::forward<T>(msg));
    }
  }

  SshMessageType msg_type() const override { return *message.key_field(); }

  template <typename Self>
  [[nodiscard]] constexpr decltype(auto) visit(this Self&& self, auto... args) {
    if (self.message.oneof.has_value()) {
      return std::visit(make_overloads<detail::top_level_visitor, Self&&>(args...), *std::forward<Self>(self).message.oneof);
    }
    using return_type = decltype(std::visit(make_overloads<detail::top_level_visitor, Self&&>(args...), *std::forward<Self>(self).message.oneof));
    if constexpr (!std::is_void_v<return_type>) {
      return return_type{};
    }
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override;

  static absl::StatusOr<Message> fromString(std::string_view str);
};

} // namespace wire
