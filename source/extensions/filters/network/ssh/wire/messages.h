#pragma once

#include <concepts>
#include <cstdint>
#include <type_traits>
#include <string>
#include <utility>

#include "source/common/fixed_string.h"

#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/message_traits.h"

namespace wire {

template <SshMessageType MT>
struct Msg : detail::MsgImplDefaults {
  static constexpr SshMessageType type = MT;
  static constexpr SshMessageType msg_type() { return MT; };
  using submsg_group = detail::TopLevelMessageGroup;
  static constexpr SshMessageType submsg_key = MT;
  static constexpr EncodingOptions submsg_key_encoding = None;
};

template <SshMessageType MT, typename T, size_t Id>
struct OverloadMsg : T {
  using inner_type = T;
  using submsg_group = detail::OverloadGroup<MT>;
  static constexpr uint64_t submsg_key = Id; // NB: this must be uint64_t; size_t is not an allowed field type
  static constexpr EncodingOptions submsg_key_encoding = None;

  OverloadMsg() = default;

  OverloadMsg(T&& t) noexcept
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
struct OverloadSet : Msg<first_type_t<Ts...>::type> {
  static_assert(all_values_equal<Ts::type...>,
                "all overloaded messages must have the same type");
  using Msg<first_type_t<Ts...>::type>::type;
  template <typename T>
    requires contains_type<T, Ts...>
  using overload_opt_for = OverloadMsg<type, T, 1 + index_of_type<T, Ts...>::value>;
  using message_type = sub_message<overload_opt_for<Ts>...>;

private:
  message_type message_;

  template <typename T>
    requires contains_type<T, Ts...>
  static consteval bool has_overload() {
    return message_type::template has_option<overload_opt_for<T>>();
  }

public:
  OverloadSet() = default;

  template <typename T>
    requires (has_overload<std::decay_t<T>>())
  explicit OverloadSet(T&& msg) {
    reset(std::forward<T>(msg));
  }

  template <typename T>
    requires (has_overload<std::decay_t<T>>())
  void reset(T&& msg) {
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

  message_type& messageForTest() {
    return message_;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return message_.decode(buffer, payload_size);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return message_.encode(buffer);
  }

  constexpr bool operator==(const OverloadSet& other) const {
    return message_ == other.message_;
  }
  constexpr bool operator!=(const OverloadSet& other) const {
    return message_ != other.message_;
  }
};

template <SshMessageType MT, fixed_string K>
struct SubMsg : detail::MsgImplDefaults {
  using submsg_group = detail::SubMsgGroup<MT>;
  static constexpr std::string_view submsg_key = K.to_string();
  static constexpr EncodingOptions submsg_key_encoding = LengthPrefixed;
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
struct KexInitMsg final : Msg<SshMessageType::KexInit> {
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
};

// https://datatracker.ietf.org/doc/html/rfc5656#section-4
struct KexEcdhInitMsg : Msg<SshMessageType::KexECDHInit> {
  field<bytes, LengthPrefixed> client_pub_key;
};

// https://datatracker.ietf.org/doc/html/rfc5656#section-4
struct KexEcdhReplyMsg : Msg<SshMessageType::KexECDHReply> {
  field<bytes, LengthPrefixed> host_key;
  field<bytes, LengthPrefixed> ephemeral_pub_key;
  field<bytes, LengthPrefixed> signature;
};

// https://datatracker.ietf.org/doc/html/draft-ietf-sshm-mlkem-hybrid-kex-03#name-pq-t-hybrid-key-exchange-me
struct KexHybridInitMsg : Msg<SshMessageType::KexHybridInit> {
  field<bytes, LengthPrefixed> client_init;
};

// https://datatracker.ietf.org/doc/html/draft-ietf-sshm-mlkem-hybrid-kex-03#name-pq-t-hybrid-key-exchange-me
struct KexHybridReplyMsg : Msg<SshMessageType::KexHybridReply> {
  field<bytes, LengthPrefixed> host_key;
  field<bytes, LengthPrefixed> server_reply;
  field<bytes, LengthPrefixed> signature;
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-10
struct ServiceRequestMsg final : Msg<SshMessageType::ServiceRequest> {
  field<std::string, LengthPrefixed> service_name;
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-10
struct ServiceAcceptMsg final : Msg<SshMessageType::ServiceAccept> {
  field<std::string, LengthPrefixed> service_name;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.1
struct SessionChannelOpenMsg : SubMsg<SshMessageType::ChannelOpen, "session"> {
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.3.2
struct X11ChannelOpenMsg : SubMsg<SshMessageType::ChannelOpen, "x11"> {
  field<std::string, LengthPrefixed> originator_address;
  field<uint32_t> originator_port;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-7.2
struct ForwardedTcpipChannelOpenMsg : SubMsg<SshMessageType::ChannelOpen, "forwarded-tcpip"> {
  field<std::string, LengthPrefixed> address_connected;
  field<uint32_t> port_connected;
  field<std::string, LengthPrefixed> originator_address;
  field<uint32_t> originator_port;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-7.2
struct DirectTcpipChannelOpenMsg : SubMsg<SshMessageType::ChannelOpen, "direct-tcpip"> {
  field<std::string, LengthPrefixed> host_to_connect;
  field<uint32_t> port_to_connect;
  field<std::string, LengthPrefixed> originator_address;
  field<uint32_t> originator_port;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
struct ChannelOpenMsg final : Msg<SshMessageType::ChannelOpen> {
  constexpr auto& channel_type(this auto& self) { return *self.request.key_field(); }
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  sub_message<SessionChannelOpenMsg,
              X11ChannelOpenMsg,
              ForwardedTcpipChannelOpenMsg,
              DirectTcpipChannelOpenMsg>
    request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
struct PtyReqChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "pty-req"> {
  field<std::string, LengthPrefixed> term_env;
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;
  field<std::string, LengthPrefixed> modes;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
struct ShellChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "shell"> {
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
struct ExecChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "exec"> {
  field<std::string, LengthPrefixed> command;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.7
struct WindowDimensionChangeChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "window-change"> {
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
struct SubsystemChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "subsystem"> {
  field<std::string, LengthPrefixed> subsystem_name;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.4
struct EnvChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "env"> {
  field<std::string, LengthPrefixed> variable_name;
  field<std::string, LengthPrefixed> variable_value;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.3.1
struct X11ReqChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "x11-req"> {
  field<bool> single_connection;
  field<std::string, LengthPrefixed> x11_authentication_protocol;
  field<std::string, LengthPrefixed> x11_authentication_cookie;
  field<uint32_t> x11_screen_number;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.10
struct ExitSignalChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "exit-signal"> {
  field<std::string, LengthPrefixed> signal_name;
  field<bool> core_dumped;
  field<std::string, LengthPrefixed> error_message;
  field<std::string, LengthPrefixed> language_tag;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.10
struct ExitStatusChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "exit-status"> {
  field<uint32_t> exit_status;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.9
struct SignalChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "signal"> {
  field<std::string, LengthPrefixed> signal_name;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.8
struct XOnXOffChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "xon-xoff"> {
  field<bool> client_can_do;
};

struct EowChannelRequestMsg final : SubMsg<SshMessageType::ChannelRequest, "eow@openssh.com"> {
};

// https://datatracker.ietf.org/doc/html/rfc4254
struct ChannelRequestMsg final : Msg<SshMessageType::ChannelRequest> {
  mutable field<uint32_t> recipient_channel;
  constexpr std::string& request_type() { return *request.key_field(); }
  field<bool> want_reply;
  sub_message<PtyReqChannelRequestMsg,
              ShellChannelRequestMsg,
              ExecChannelRequestMsg,
              WindowDimensionChangeChannelRequestMsg,
              SubsystemChannelRequestMsg,
              EnvChannelRequestMsg,
              X11ReqChannelRequestMsg,
              ExitSignalChannelRequestMsg,
              ExitStatusChannelRequestMsg,
              SignalChannelRequestMsg,
              XOnXOffChannelRequestMsg,
              EowChannelRequestMsg>
    request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
struct ChannelOpenConfirmationMsg final : Msg<SshMessageType::ChannelOpenConfirmation> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  field<bytes> extra;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
struct ChannelOpenFailureMsg final : Msg<SshMessageType::ChannelOpenFailure> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
struct ChannelWindowAdjustMsg final : Msg<SshMessageType::ChannelWindowAdjust> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> bytes_to_add;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
struct ChannelDataMsg final : Msg<SshMessageType::ChannelData> {
  mutable field<uint32_t> recipient_channel;
  field<bytes, LengthPrefixed> data;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
struct ChannelExtendedDataMsg final : Msg<SshMessageType::ChannelExtendedData> {
  mutable field<uint32_t> recipient_channel;
  field<uint32_t> data_type_code;
  field<bytes, LengthPrefixed> data;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.3
struct ChannelEOFMsg final : Msg<SshMessageType::ChannelEOF> {
  mutable field<uint32_t> recipient_channel;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.3
struct ChannelCloseMsg final : Msg<SshMessageType::ChannelClose> {
  mutable field<uint32_t> recipient_channel;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.4
struct ChannelSuccessMsg final : Msg<SshMessageType::ChannelSuccess> {
  mutable field<uint32_t> recipient_channel;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.4
struct ChannelFailureMsg final : Msg<SshMessageType::ChannelFailure> {
  mutable field<uint32_t> recipient_channel;
};

struct HostKeysProveRequestMsg final : SubMsg<SshMessageType::GlobalRequest, "hostkeys-prove-00@openssh.com"> {
  field<bytes_list, LengthPrefixed> hostkeys;
};

struct HostKeysMsg final : SubMsg<SshMessageType::GlobalRequest, "hostkeys-00@openssh.com"> {
  field<bytes_list, LengthPrefixed> hostkeys;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-7.1
struct TcpipForwardMsg final : SubMsg<SshMessageType::GlobalRequest, "tcpip-forward"> {
  field<std::string, LengthPrefixed> remote_address;
  field<uint32_t> remote_port;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-7.1
struct CancelTcpipForwardMsg final : SubMsg<SshMessageType::GlobalRequest, "cancel-tcpip-forward"> {
  field<std::string, LengthPrefixed> remote_address;
  field<uint32_t> remote_port;
};

// https://datatracker.ietf.org/doc/html/rfc4254#section-4
struct GlobalRequestMsg final : Msg<SshMessageType::GlobalRequest> {
  constexpr std::string& request_name() { return *request.key_field(); }
  field<bool> want_reply;
  sub_message<HostKeysProveRequestMsg,
              HostKeysMsg,
              TcpipForwardMsg,
              CancelTcpipForwardMsg>
    request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

struct HostKeysProveResponseMsg final : SubMsg<SshMessageType::RequestSuccess, "hostkeys-prove-00@openssh.com"> {
  field<bytes_list, LengthPrefixed> signatures;
};

struct TcpipForwardResponseMsg final : SubMsg<SshMessageType::RequestSuccess, "tcpip-forward"> {
  field<uint32_t> server_port;
};

// // https://datatracker.ietf.org/doc/html/rfc4254#section-4
struct GlobalRequestSuccessMsg final : Msg<SshMessageType::RequestSuccess> {
  sub_message<HostKeysProveResponseMsg,
              TcpipForwardResponseMsg>
    response;

  template <typename T>
    requires (decltype(response)::has_option<T>())
  absl::Status resolve() {
    using key_type = decltype(response)::key_type;
    response.key_field() = key_type{T::submsg_key};
    return response.decodeUnknown().status();
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

// // https://datatracker.ietf.org/doc/html/rfc4254#section-4
struct GlobalRequestFailureMsg final : Msg<SshMessageType::RequestFailure> {
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-11.2
struct IgnoreMsg final : Msg<SshMessageType::Ignore> {
  field<bytes, LengthPrefixed> data;
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-11.3
struct DebugMsg final : Msg<SshMessageType::Debug> {
  field<bool> always_display;
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-11.4
struct UnimplementedMsg final : Msg<SshMessageType::Unimplemented> {
  // FIXME: the sequence numbers in this message are likely going to be wrong, need to adjust them
  field<uint32_t> sequence_number;
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-7
struct PubKeyUserAuthRequestMsg final : SubMsg<SshMessageType::UserAuthRequest, "publickey"> {
  field<bool> has_signature;
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;
  field<bytes, LengthPrefixed> signature;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

// https://datatracker.ietf.org/doc/html/rfc4256#section-3.1
struct KeyboardInteractiveUserAuthRequestMsg final : SubMsg<SshMessageType::UserAuthRequest, "keyboard-interactive"> {
  field<std::string, LengthPrefixed> language_tag;
  field<string_list, NameListFormat> submethods;
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-5.2
struct NoneAuthRequestMsg final : SubMsg<SshMessageType::UserAuthRequest, "none"> {
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-5
struct UserAuthRequestMsg final : Msg<SshMessageType::UserAuthRequest> {
  field<std::string, LengthPrefixed> username;
  field<std::string, LengthPrefixed> service_name;
  constexpr std::string& method_name() { return *request.key_field(); }
  sub_message<PubKeyUserAuthRequestMsg,
              KeyboardInteractiveUserAuthRequestMsg,
              NoneAuthRequestMsg>
    request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

struct UserAuthInfoPrompt {
  field<std::string, LengthPrefixed> prompt;
  field<bool> echo;

  constexpr bool operator==(const UserAuthInfoPrompt&) const = default;
  constexpr bool operator!=(const UserAuthInfoPrompt&) const = default;

  // implements Reader
  friend size_t read(Envoy::Buffer::Instance& buffer, UserAuthInfoPrompt& prompt, size_t payload_size);
  // implements Writer
  friend size_t write(Envoy::Buffer::Instance& buffer, const UserAuthInfoPrompt& prompt);
};

// https://datatracker.ietf.org/doc/html/rfc4256#section-3.2
struct UserAuthInfoRequestMsg : Msg<SshMessageType::UserAuthInfoRequest> {
  field<std::string, LengthPrefixed> name;
  field<std::string, LengthPrefixed> instruction;
  field<std::string, LengthPrefixed> language_tag;
  field<std::vector<UserAuthInfoPrompt>, ListSizePrefixed> prompts;
};

// https://datatracker.ietf.org/doc/html/rfc4256#section-3.2
struct UserAuthInfoResponseMsg : Msg<SshMessageType::UserAuthInfoResponse> {
  field<string_list, LengthPrefixed | ListSizePrefixed> responses;
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-5.4
struct UserAuthBannerMsg final : Msg<SshMessageType::UserAuthBanner> {
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
struct UserAuthFailureMsg final : Msg<SshMessageType::UserAuthFailure> {
  field<string_list, NameListFormat> methods;
  field<bool> partial;
};

// https://datatracker.ietf.org/doc/html/rfc4253#section-11.1
struct DisconnectMsg final : Msg<SshMessageType::Disconnect> {
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
struct UserAuthSuccessMsg final : Msg<SshMessageType::UserAuthSuccess> {
};

// // https://datatracker.ietf.org/doc/html/rfc4253#section-7.3
struct NewKeysMsg final : Msg<SshMessageType::NewKeys> {
};

// https://datatracker.ietf.org/doc/html/rfc4252#section-7
struct UserAuthPubKeyOkMsg : Msg<SshMessageType::UserAuthPubKeyOk> {
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;
};

// https://datatracker.ietf.org/doc/html/rfc8308#section-3.1
struct ServerSigAlgsExtension final : SubMsg<SshMessageType::ExtInfo, "server-sig-algs"> {
  field<string_list, NameListFormat> public_key_algorithms_accepted;
};

struct PingExtension final : SubMsg<SshMessageType::ExtInfo, "ping@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

struct ExtInfoInAuthExtension final : SubMsg<SshMessageType::ExtInfo, "ext-info-in-auth@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

// The Extension struct itself is a Reader/Writer, since it is used as the value type of a field.
// Sub-messages can't appear more than once, as they do not encode their own size information.
// Extension is implemented in terms of a sub_message, but that is only an implementation detail.
struct Extension {
  constexpr std::string& extension_name() { return *extension.key_field(); }
  sub_message<ServerSigAlgsExtension,
              PingExtension,
              ExtInfoInAuthExtension>
    extension;

  Extension() = default;
  template <typename T>
    requires (decltype(extension)::has_option<T>())
  explicit Extension(T&& ext) {
    extension.reset(std::forward<T>(ext));
  }

  constexpr bool operator==(const Extension&) const = default;
  constexpr bool operator!=(const Extension&) const = default;

  // implements Reader
  friend size_t read(Envoy::Buffer::Instance& buffer, Extension& ext, size_t payload_size);
  // implements Writer
  friend size_t write(Envoy::Buffer::Instance& buffer, const Extension& ext);
};

struct ExtInfoMsg final : Msg<SshMessageType::ExtInfo> {
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

  template <typename T>
  std::optional<T> getExtension() const {
    for (const auto& ext : *extensions) {
      if (ext.extension.holds_alternative<T>()) {
        return {ext.extension.get<T>()};
      }
    }
    return std::nullopt;
  }
};

struct PingMsg final : Msg<SshMessageType::Ping> {
  field<std::string, LengthPrefixed> data;
};

struct PongMsg final : Msg<SshMessageType::Pong> {
  field<std::string, LengthPrefixed> data;
};

namespace detail {

using top_level_message = sub_message<                      // Message ID
  DisconnectMsg,                                            // 1
  IgnoreMsg,                                                // 2
  UnimplementedMsg,                                         // 3
  DebugMsg,                                                 // 4
  ServiceRequestMsg,                                        // 5
  ServiceAcceptMsg,                                         // 6
  ExtInfoMsg,                                               // 7
  KexInitMsg,                                               // 20
  NewKeysMsg,                                               // 21
  OverloadSet<KexEcdhInitMsg, KexHybridInitMsg>,            // 30 (3 overloads, 2 supported)
  OverloadSet<KexEcdhReplyMsg, KexHybridReplyMsg>,          // 31 (4 overloads, 2 supported)
  UserAuthRequestMsg,                                       // 50
  UserAuthFailureMsg,                                       // 51
  UserAuthSuccessMsg,                                       // 52
  UserAuthBannerMsg,                                        // 53
  OverloadSet<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>, // 60 (4 overloads, 2 supported)
  OverloadSet<UserAuthInfoResponseMsg>,                     // 61 (2 overloads, 1 supported)
  GlobalRequestMsg,                                         // 80
  GlobalRequestSuccessMsg,                                  // 81
  GlobalRequestFailureMsg,                                  // 82
  ChannelOpenMsg,                                           // 90
  ChannelOpenConfirmationMsg,                               // 91
  ChannelOpenFailureMsg,                                    // 92
  ChannelWindowAdjustMsg,                                   // 93
  ChannelDataMsg,                                           // 94
  ChannelExtendedDataMsg,                                   // 95
  ChannelEOFMsg,                                            // 96
  ChannelCloseMsg,                                          // 97
  ChannelRequestMsg,                                        // 98
  ChannelSuccessMsg,                                        // 99
  ChannelFailureMsg,                                        // 100
  PingMsg,                                                  // 192
  PongMsg>;                                                 // 193

static_assert(std::regular<top_level_message>);

// These definitions allow us to look up the matching overload set a particular message is part of.
// For any of the supported messages that are overloaded, overload_set_for<T> will return the
// OverloadSet<...> containing T (and possibly other overloads) present in top_level_message.
//
// If the types in top_level_message are updated, make sure these definitions are also kept in sync
// (they could be pulled automatically from top_level_message but it's not worth the complexity).
template <> struct overload_set_for<KexEcdhInitMsg> : std::type_identity<OverloadSet<KexEcdhInitMsg, KexHybridInitMsg>> {};
template <> struct overload_set_for<KexEcdhReplyMsg> : std::type_identity<OverloadSet<KexEcdhReplyMsg, KexHybridReplyMsg>> {};
template <> struct overload_set_for<KexHybridInitMsg> : std::type_identity<OverloadSet<KexEcdhInitMsg, KexHybridInitMsg>> {};
template <> struct overload_set_for<KexHybridReplyMsg> : std::type_identity<OverloadSet<KexEcdhReplyMsg, KexHybridReplyMsg>> {};
template <> struct overload_set_for<UserAuthPubKeyOkMsg> : std::type_identity<OverloadSet<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>> {};
template <> struct overload_set_for<UserAuthInfoRequestMsg> : std::type_identity<OverloadSet<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>> {};
template <> struct overload_set_for<UserAuthInfoResponseMsg> : std::type_identity<OverloadSet<UserAuthInfoResponseMsg>> {};

template <DecayedType T>
  requires (top_level_message::template has_option<overload_set_for_t<T>>())
struct is_top_level_message<T> : std::true_type {};

template <DecayedType... Args>
struct is_overload_set<OverloadSet<Args...>> : std::true_type {};

} // namespace detail

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
    if constexpr (!std::is_same_v<std::decay_t<T>, detail::overload_set_for_t<std::decay_t<T>>>) {
      message.reset(detail::overload_set_for_t<std::decay_t<T>>{std::forward<T>(msg)});
    } else {
      message.reset(std::forward<T>(msg));
    }
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
      return std::visit(make_overloads<detail::top_level_visitor, Self&&>(args...), *std::forward<Self>(self).message.oneof);
    }
    using return_type = decltype(std::visit(make_overloads<detail::top_level_visitor, Self&&>(args...), *std::forward<Self>(self).message.oneof));
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

extern template struct BasicMessage<detail::top_level_message>;
using Message = BasicMessage<detail::top_level_message>;
using MessagePtr = std::unique_ptr<Message>;

using top_level_channel_message = wire::sub_message<
  ChannelRequestMsg,
  ChannelOpenConfirmationMsg,
  ChannelOpenFailureMsg,
  ChannelWindowAdjustMsg,
  ChannelDataMsg,
  ChannelExtendedDataMsg,
  ChannelEOFMsg,
  ChannelCloseMsg,
  ChannelSuccessMsg,
  ChannelFailureMsg>;
using ChannelMessage = wire::BasicMessage<top_level_channel_message>;

} // namespace wire
