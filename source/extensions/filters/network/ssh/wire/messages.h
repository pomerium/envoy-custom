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
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/message_traits.h"

namespace wire {

struct BaseSshMsg {
  virtual ~BaseSshMsg() = default;
  virtual SshMessageType msg_type() const PURE; // NOLINT
};

struct SshMsg : public virtual BaseSshMsg {
  virtual absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept PURE;
  virtual absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept PURE;

  template <SshStringType T>
  absl::StatusOr<T> encodeTo() const {
    Envoy::Buffer::OwnedImpl buf;
    if (auto r = this->encode(buf); !r.ok()) {
      return r.status();
    }
    return flushTo<T>(buf);
  }

protected:
  static void peekType(Envoy::Buffer::Instance& buffer, field<SshMessageType>* out) {
    *out = buffer.peekInt<SshMessageType>();
  }

  static size_t readType(Envoy::Buffer::Instance& buffer, field<SshMessageType>* out) {
    *out = buffer.drainInt<SshMessageType>();
    return 1;
  }
};

using SshMsgPtr = std::unique_ptr<SshMsg>;

template <SshMessageType MT>
struct MsgType : public virtual BaseSshMsg {
  static constexpr SshMessageType type = MT;

  bool operator==(const MsgType& other) const {
    return type == other.type;
  };

  SshMessageType msg_type() const override {
    return type;
  }
};

template <SshMessageType MT>
struct Msg : SshMsg, MsgType<MT> {
  using submsg_group = detail::TopLevelMessageGroup;
  static constexpr SshMessageType submsg_key = MT;
  static constexpr EncodingOptions submsg_key_encoding = None;
};

template <SshMessageType MT, typename T, size_t Index>
struct OverloadMsg : T {
  using submsg_group = detail::OverloadGroup<MT>;
  static constexpr uint64_t submsg_key = Index; // NB: this must be uint64_t; size_t is not an allowed field type
  static constexpr EncodingOptions submsg_key_encoding = None;

  OverloadMsg() = default;

  OverloadMsg(T&& t)
      : T(std::move(t)) {};
  OverloadMsg(const T& t)
      : T(t) {};
};

template <typename T>
concept ChannelMsg = requires(T t) {
  { t.getRecipientChannel() } -> std::same_as<field<uint32_t>&>;
};

template <typename... Ts>
struct OverloadedMessage : Msg<first_type_t<Ts...>::type> {
  static_assert(all_values_equal<Ts::type...>,
                "all overloaded messages must have the same type");
  using Msg<first_type_t<Ts...>::type>::type;

  template <typename T>
  using overload_opt_for = OverloadMsg<type, T, index_of_type<T, Ts...>::value>;

private:
  sub_message<overload_opt_for<Ts>...> message_{defer_decoding};
  std::optional<field<uint64_t>> key_;

  template <typename T>
  static constexpr bool has_overload() {
    return std::decay_t<decltype(message_)>::template has_option<overload_opt_for<T>>();
  }

public:
  OverloadedMessage() = default;

  template <typename T>
    requires (has_overload<std::decay_t<T>>())
  explicit OverloadedMessage(T&& msg) {
    key_ = field<uint64_t>{};
    message_.setKeyField(*key_);
    message_.reset(overload_opt_for<std::decay_t<T>>{std::forward<T>(msg)});
  }

  template <typename T>
    requires (has_overload<T>())
  Envoy::OptRef<T> resolve() {
    constexpr auto index = index_of_type<T, Ts...>::value;
    if (!key_.has_value()) {
      key_ = field<uint64_t>{};
      *key_ = index;
      message_.setKeyField(*key_);
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

template <auto N>
struct Key {
  constexpr Key(const char (&str)[N]) {
    std::copy_n(static_cast<const char*>(str), N, static_cast<char*>(value));
  }
  constexpr std::string_view to_string() const {
    return static_cast<const char*>(value);
  }
  char value[N];
};

template <SshMessageType MT, auto Key>
struct SubMsg {
  virtual ~SubMsg() = default;
  using submsg_group = detail::SubMsgGroup<MT>;
  static constexpr std::string_view submsg_key = Key.to_string();
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

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     cookie,
                     kex_algorithms,
                     server_host_key_algorithms,
                     encryption_algorithms_client_to_server,
                     encryption_algorithms_server_to_client,
                     mac_algorithms_client_to_server,
                     mac_algorithms_server_to_client,
                     compression_algorithms_client_to_server,
                     compression_algorithms_server_to_client,
                     languages_client_to_server,
                     languages_server_to_client,
                     first_kex_packet_follows,
                     reserved);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     cookie,
                     kex_algorithms,
                     server_host_key_algorithms,
                     encryption_algorithms_client_to_server,
                     encryption_algorithms_server_to_client,
                     mac_algorithms_client_to_server,
                     mac_algorithms_server_to_client,
                     compression_algorithms_client_to_server,
                     compression_algorithms_server_to_client,
                     languages_client_to_server,
                     languages_server_to_client,
                     first_kex_packet_follows,
                     reserved);
  }
};

struct KexEcdhInitMessage : Msg<SshMessageType::KexECDHInit> {
  field<bytes, LengthPrefixed> client_pub_key;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     client_pub_key);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     client_pub_key);
  }
};

struct KexEcdhReplyMsg : Msg<SshMessageType::KexECDHReply> {
  field<bytes, LengthPrefixed> host_key;
  field<bytes, LengthPrefixed> ephemeral_pub_key;
  field<bytes, LengthPrefixed> signature;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     host_key,
                     ephemeral_pub_key,
                     signature);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     host_key,
                     ephemeral_pub_key,
                     signature);
  }
};

struct ServiceRequestMsg : Msg<SshMessageType::ServiceRequest> {
  field<std::string, LengthPrefixed> service_name;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     service_name);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     service_name);
  }
};

struct ServiceAcceptMsg : Msg<SshMessageType::ServiceAccept> {
  field<std::string, LengthPrefixed> service_name;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     service_name);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     service_name);
  }
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

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     channel_type,
                     sender_channel,
                     initial_window_size,
                     max_packet_size,
                     extra);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     channel_type,
                     sender_channel,
                     initial_window_size,
                     max_packet_size,
                     extra);
  }
};

struct PtyReqChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest, Key("pty-req")> {
  field<std::string, LengthPrefixed> term_env;
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;
  field<std::string, LengthPrefixed> modes;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeSequence(buffer, payload_size,
                          term_env,
                          width_columns,
                          height_rows,
                          width_px,
                          height_px,
                          modes);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeSequence(buffer,
                          term_env,
                          width_columns,
                          height_rows,
                          width_px,
                          height_px,
                          modes);
  }
};

struct ShellChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest, Key("shell")> {
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

struct WindowDimensionChangeChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest, Key("window-change")> {
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeSequence(buffer, payload_size,
                          width_columns,
                          height_rows,
                          width_px,
                          height_px);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeSequence(buffer,
                          width_columns,
                          height_rows,
                          width_px,
                          height_px);
  }
};

struct ChannelRequestMsg : Msg<SshMessageType::ChannelRequest> {
  field<uint32_t> recipient_channel;
  field<std::string, LengthPrefixed> request_type;
  field<bool> want_reply;
  sub_message<PtyReqChannelRequestMsg, ShellChannelRequestMsg> msg{request_type};

  ChannelRequestMsg() = default;
  ChannelRequestMsg(ChannelRequestMsg&&) = default;
  ChannelRequestMsg& operator=(const ChannelRequestMsg&) = delete;
  ChannelRequestMsg& operator=(ChannelRequestMsg&&) = default;
  ChannelRequestMsg(const ChannelRequestMsg& other)
      : recipient_channel(other.recipient_channel),
        request_type(other.request_type),
        want_reply(other.want_reply),
        msg(other.msg) {
    msg.setKeyField(request_type);
    auto _ = msg.decodeUnknown(); // TODO: handle this error
  }

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel,
                     request_type,
                     want_reply,
                     msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel,
                     request_type,
                     want_reply,
                     msg);
  }
};

struct ChannelOpenConfirmationMsg : Msg<SshMessageType::ChannelOpenConfirmation> {
  field<uint32_t> recipient_channel;
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  field<bytes> extra;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel,
                     sender_channel,
                     initial_window_size,
                     max_packet_size,
                     extra);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel,
                     sender_channel,
                     initial_window_size,
                     max_packet_size,
                     extra);
  }
};

struct ChannelOpenFailureMsg : Msg<SshMessageType::ChannelOpenFailure> {
  field<uint32_t> recipient_channel;
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel,
                     reason_code,
                     description,
                     language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel,
                     reason_code,
                     description,
                     language_tag);
  }
};

struct ChannelWindowAdjustMsg : Msg<SshMessageType::ChannelWindowAdjust> {
  field<uint32_t> recipient_channel;
  field<uint32_t> bytes_to_add;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel,
                     bytes_to_add);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel,
                     bytes_to_add);
  }
};

struct ChannelDataMsg : Msg<SshMessageType::ChannelData> {
  field<uint32_t> recipient_channel;
  field<bytes, LengthPrefixed> data;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel,
                     data);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel,
                     data);
  }
};

struct ChannelExtendedDataMsg : Msg<SshMessageType::ChannelExtendedData> {
  field<uint32_t> recipient_channel;
  field<uint32_t> data_type_code;
  field<bytes, LengthPrefixed> data;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel,
                     data_type_code,
                     data);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel,
                     data_type_code,
                     data);
  }
};

struct ChannelEOFMsg : Msg<SshMessageType::ChannelEOF> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel);
  }
};

struct ChannelCloseMsg : Msg<SshMessageType::ChannelClose> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel);
  }
};

struct ChannelSuccessMsg : Msg<SshMessageType::ChannelSuccess> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel);
  }
};

struct ChannelFailureMsg : Msg<SshMessageType::ChannelFailure> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& getRecipientChannel() {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     recipient_channel);
  }
};

struct HostKeysProveRequestMsg : SubMsg<SshMessageType::GlobalRequest, Key("hostkeys-prove-00@openssh.com")> {
  field<bytes_list, LengthPrefixed> hostkeys;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t len) override {
    return decodeSequence(buffer, len, hostkeys);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeSequence(buffer, hostkeys);
  }
};

struct HostKeysMsg : SubMsg<SshMessageType::GlobalRequest, Key("hostkeys-00@openssh.com")> {
  field<bytes_list, LengthPrefixed> hostkeys;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t len) override {
    return decodeSequence(buffer, len, hostkeys);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeSequence(buffer, hostkeys);
  }
};

struct GlobalRequestMsg : Msg<SshMessageType::GlobalRequest> {
  field<std::string, LengthPrefixed> request_name;
  field<bool> want_reply;
  sub_message<HostKeysProveRequestMsg, HostKeysMsg> msg{request_name};

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     request_name,
                     want_reply,
                     msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     request_name,
                     want_reply,
                     msg);
  }
};

struct HostKeysProveResponseMsg : SubMsg<SshMessageType::RequestSuccess, Key("hostkeys-prove-00@openssh.com")> {
  field<bytes_list, LengthPrefixed> signatures;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t len) override {
    return decodeSequence(buffer, len, signatures);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeSequence(buffer, signatures);
  };
};

struct GlobalRequestSuccessMsg : Msg<SshMessageType::RequestSuccess> {
  sub_message<HostKeysProveResponseMsg> msg{defer_decoding};

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     msg);
  }
};

struct GlobalRequestFailureMsg : EmptyMsg<SshMessageType::RequestFailure> {};

struct IgnoreMsg : Msg<SshMessageType::Ignore> {
  field<bytes, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     data);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     data);
  }
};

struct DebugMsg : Msg<SshMessageType::Debug> {
  field<bool> always_display;
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     always_display,
                     message,
                     language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     always_display,
                     message,
                     language_tag);
  }
};

struct UnimplementedMsg : Msg<SshMessageType::Unimplemented> {
  // FIXME: the sequence numbers in this message are likely going to be wrong, need to adjust them
  field<uint32_t> sequence_number;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     sequence_number);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     sequence_number);
  }
};

struct PubKeyUserAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest, Key("publickey")> {
  field<bool> has_signature;
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;
  field<bytes, LengthPrefixed | Conditional> signature;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeSequence(buffer, payload_size,
                          has_signature,
                          public_key_alg,
                          public_key,
                          signature.enableIf(has_signature));
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    // The check on signature here is important; even if signature was empty, writeString would
    // still append a 4-byte length field containing 0. We also can't check based on has_signature,
    // because the signature is computed over the wire encoding of this message and requires
    // has_signature to be true (see RFC4252 sec. 7)
    return encodeSequence(buffer,
                          has_signature,
                          public_key_alg,
                          public_key,
                          signature.enableIf(!signature->empty()));
  }
};

struct KeyboardInteractiveUserAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest, Key("keyboard-interactive")> {
  field<std::string, LengthPrefixed> language_tag;
  field<string_list, NameListFormat> submethods;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeSequence(buffer, payload_size,
                          language_tag,
                          submethods);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeSequence(buffer,
                          language_tag,
                          submethods);
  }
};

struct NoneAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest, Key("none")> {
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
  field<std::string, LengthPrefixed> method_name;
  sub_message<
    PubKeyUserAuthRequestMsg,
    KeyboardInteractiveUserAuthRequestMsg,
    NoneAuthRequestMsg>
    msg{method_name};

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     username,
                     service_name,
                     method_name,
                     msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     username,
                     service_name,
                     method_name,
                     msg);
  }
};

struct UserAuthInfoPrompt {
  field<std::string, LengthPrefixed> prompt;
  field<bool> echo;
};

// implements Reader
inline size_t read(Envoy::Buffer::Instance& buffer, UserAuthInfoPrompt& prompt, size_t payload_size) {
  auto n = decodeSequence(buffer, payload_size, prompt.prompt, prompt.echo);
  if (!n.ok()) {
    throw Envoy::EnvoyException(std::string(n.status().message()));
  }
  return *n;
}

// implements Writer
inline size_t write(Envoy::Buffer::Instance& buffer, const UserAuthInfoPrompt& prompt) {
  auto n = encodeSequence(buffer, prompt.prompt, prompt.echo);
  if (!n.ok()) {
    throw Envoy::EnvoyException(std::string(n.status().message()));
  }
  return *n;
}

struct UserAuthInfoRequestMsg : Msg<SshMessageType::UserAuthInfoRequest> {
  field<std::string, LengthPrefixed> name;
  field<std::string, LengthPrefixed> instruction;
  field<std::string, LengthPrefixed> language_tag;
  field<std::vector<UserAuthInfoPrompt>, ListSizePrefixed> prompts;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     name,
                     instruction,
                     language_tag,
                     prompts);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     name,
                     instruction,
                     language_tag,
                     prompts);
  }
};

struct UserAuthInfoResponseMsg : Msg<SshMessageType::UserAuthInfoResponse> {
  field<string_list, LengthPrefixed | ListSizePrefixed> responses;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size, responses);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type, responses);
  }
};

struct UserAuthBannerMsg : Msg<SshMessageType::UserAuthBanner> {
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     message,
                     language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     message,
                     language_tag);
  }
};

struct UserAuthFailureMsg : Msg<SshMessageType::UserAuthFailure> {
  field<string_list, NameListFormat> methods;
  field<bool> partial;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size, methods, partial);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type, methods, partial);
  }
};

struct DisconnectMsg : Msg<SshMessageType::Disconnect> {
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     reason_code,
                     description,
                     language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     reason_code,
                     description,
                     language_tag);
  }
};

struct UserAuthSuccessMsg : EmptyMsg<SshMessageType::UserAuthSuccess> {};
struct NewKeysMsg : EmptyMsg<SshMessageType::NewKeys> {};

struct UserAuthPubKeyOkMsg : Msg<SshMessageType::UserAuthPubKeyOk> {
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     public_key_alg,
                     public_key);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     public_key_alg,
                     public_key);
  }
};

namespace detail {

using top_level_message = sub_message<
  DisconnectMsg,                                                  // 1
  IgnoreMsg,                                                      // 2
  UnimplementedMsg,                                               // 3
  DebugMsg,                                                       // 4
  ServiceRequestMsg,                                              // 5
  ServiceAcceptMsg,                                               // 6
  KexInitMessage,                                                 // 7
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
  ChannelFailureMsg>;                                             // 100

template <> struct overload_for<KexEcdhInitMessage> : std::type_identity<OverloadedMessage<KexEcdhInitMessage>> {};
template <> struct overload_for<KexEcdhReplyMsg> : std::type_identity<OverloadedMessage<KexEcdhReplyMsg>> {};
template <> struct overload_for<UserAuthPubKeyOkMsg> : std::type_identity<OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>> {};
template <> struct overload_for<UserAuthInfoRequestMsg> : std::type_identity<OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg>> {};
template <> struct overload_for<UserAuthInfoResponseMsg> : std::type_identity<OverloadedMessage<UserAuthInfoResponseMsg>> {};

} // namespace detail

struct Message : SshMsg {
  field<SshMessageType> message_type;
  detail::top_level_message message{message_type};

  Message() = default;

  template <typename T>
    requires (!std::same_as<std::decay_t<T>, Message>)
  Message(T&& msg) {
    if constexpr (!std::is_same_v<std::decay_t<T>, detail::overload_for_t<std::decay_t<T>>>) {
      message.reset(detail::overload_for_t<std::decay_t<T>>{std::forward<T>(msg)});
    } else {
      message.reset(std::forward<T>(msg));
    }
  }

  SshMessageType msg_type() const override { return message_type; }

  decltype(auto) visit(this auto& self, auto... args) {
    return std::visit(detail::top_level_message_visitor{args...}, self.message.oneof);
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    peekType(buffer, &message_type);
    return message.decode(buffer, payload_size);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return message.encode(buffer);
  }

  static absl::StatusOr<Message> fromString(std::string_view str) {
    Message m{};
    auto stat = with_buffer_view(str, [&m](Envoy::Buffer::Instance& buffer) {
      return m.decode(buffer, buffer.length());
    });
    if (!stat.ok()) {
      return stat.status();
    }
    return m;
  }
};

} // namespace wire
