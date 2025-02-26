#pragma once

#include <cstdint>
#include <type_traits>
#include <string>

#include "source/common/buffer/buffer_impl.h"

#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/field.h"

namespace wire {

struct BaseSshMsg {
  virtual ~BaseSshMsg() = default;
  virtual SshMessageType msg_type() const PURE;

  virtual bool is_channel_message() const {
    return false;
  }
};

struct SshMsg : public virtual BaseSshMsg {
  virtual ~SshMsg() = default;

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

struct ChannelMsg : SshMsg {
  virtual field<uint32_t>& get_recipient_channel() PURE;
};

template <SshMessageType MT>
struct MsgType : public virtual BaseSshMsg {
  static constexpr SshMessageType type = MT;

  bool operator==(const MsgType& other) const {
    return type == other.type;
  };

  SshMessageType msg_type() const override {
    return type;
  }

  bool is_channel_message() const override {
    return is_channel_msg_v<MT>;
  }
};

template <SshMessageType T, typename = void>
struct Msg : SshMsg, MsgType<T> {
};

template <SshMessageType T>
struct Msg<T, std::enable_if_t<is_channel_msg_v<T>>> : ChannelMsg, MsgType<T> {};

template <auto N>
struct Key {
  constexpr Key(const char (&str)[N]) {
    std::copy_n(str, N, value);
  }
  constexpr std::string_view to_string() const {
    return value;
  }
  char value[N];
};

template <SshMessageType MT, auto Key>
struct SubMsg {
  virtual ~SubMsg() = default;
  static constexpr auto submsg_type = MT;
  static constexpr auto submsg_key = Key.to_string();

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
  field<uint8_t> first_kex_packet_follows;
  field<uint32_t> reserved;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
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
    return encodeMsg<type>(buffer,
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
    return decodeMsg<type>(buffer, payload_size,
                           client_pub_key);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           client_pub_key);
  }
};

struct KexEcdhReplyMsg : Msg<SshMessageType::KexECDHReply> {
  field<bytes, LengthPrefixed> host_key;
  field<bytes, LengthPrefixed> ephemeral_pub_key;
  field<bytes, LengthPrefixed> signature;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           host_key,
                           ephemeral_pub_key,
                           signature);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           host_key,
                           ephemeral_pub_key,
                           signature);
  }
};

struct ServiceRequestMsg : Msg<SshMessageType::ServiceRequest> {
  field<std::string, LengthPrefixed> service_name;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           service_name);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           service_name);
  }
};

struct ServiceAcceptMsg : Msg<SshMessageType::ServiceAccept> {
  field<std::string, LengthPrefixed> service_name;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           service_name);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           service_name);
  }
};

template <SshMessageType T>
struct EmptyMsg : Msg<T> {
  using Msg<T>::type;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer);
  }
};

struct ChannelOpenMsg : Msg<SshMessageType::ChannelOpen> {
  field<std::string, LengthPrefixed> channel_type;
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  field<bytes> extra;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           channel_type,
                           sender_channel,
                           initial_window_size,
                           max_packet_size,
                           extra);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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

struct ChannelRequestMsg : Msg<SshMessageType::ChannelRequest> {
  field<uint32_t> recipient_channel;
  field<std::string, LengthPrefixed> request_type;
  field<bool> want_reply;
  sub_message<PtyReqChannelRequestMsg> msg{request_type};

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           request_type,
                           want_reply,
                           msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           sender_channel,
                           initial_window_size,
                           max_packet_size,
                           extra);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           reason_code,
                           description,
                           language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel,
                           reason_code,
                           description,
                           language_tag);
  }
};

struct ChannelWindowAdjustMsg : Msg<SshMessageType::ChannelWindowAdjust> {
  field<uint32_t> recipient_channel;
  field<uint32_t> bytes_to_add;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           bytes_to_add);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel,
                           bytes_to_add);
  }
};

struct ChannelDataMsg : Msg<SshMessageType::ChannelData> {
  field<uint32_t> recipient_channel;
  field<bytes> data;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           data);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel,
                           data);
  }
};

struct ChannelExtendedDataMsg : Msg<SshMessageType::ChannelExtendedData> {
  field<uint32_t> recipient_channel;
  field<uint32_t> data_type_code;
  field<bytes> data;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           data_type_code,
                           data);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel,
                           data_type_code,
                           data);
  }
};

struct ChannelEOFMsg : Msg<SshMessageType::ChannelEOF> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct ChannelCloseMsg : Msg<SshMessageType::ChannelClose> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct ChannelSuccessMsg : Msg<SshMessageType::ChannelSuccess> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct ChannelFailureMsg : Msg<SshMessageType::ChannelFailure> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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
    return decodeMsg<type>(buffer, payload_size,
                           request_name,
                           want_reply,
                           msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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
    return decodeMsg<type>(buffer, payload_size,
                           msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           msg);
  }
};

struct GlobalRequestFailureMsg : EmptyMsg<SshMessageType::RequestFailure> {};

struct IgnoreMsg : Msg<SshMessageType::Ignore> {
  field<bytes, LengthPrefixed> data;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           data);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           data);
  }
};

struct DebugMsg : Msg<SshMessageType::Debug> {
  field<bool> always_display;
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           always_display,
                           message,
                           language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           always_display,
                           message,
                           language_tag);
  }
};

struct UnimplementedMsg : Msg<SshMessageType::Unimplemented> {
  // FIXME: the sequence numbers in this message are likely going to be wrong, need to adjust them
  field<uint32_t> sequence_number;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           sequence_number);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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
                          signature.enable_if(has_signature));
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
                          signature.enable_if(!signature->empty()));
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

  // UserAuthRequestMsg()
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           username,
                           service_name,
                           method_name,
                           msg);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           username,
                           service_name,
                           method_name,
                           msg);
  }
};

struct userAuthInfoPrompt {
  field<std::string, LengthPrefixed> prompt;
  field<bool> echo;
};

// implements Reader
inline size_t read(Envoy::Buffer::Instance& buffer, userAuthInfoPrompt& prompt, size_t payload_size) {
  auto n = decodeSequence(buffer, payload_size, prompt.prompt, prompt.echo);
  if (!n.ok()) {
    throw Envoy::EnvoyException(std::string(n.status().message()));
  }
  return *n;
}

// implements Writer
inline size_t write(Envoy::Buffer::Instance& buffer, const userAuthInfoPrompt& prompt) {
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
  field<std::vector<userAuthInfoPrompt>, ListSizePrefixed> prompts;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           name,
                           instruction,
                           language_tag,
                           prompts);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           name,
                           instruction,
                           language_tag,
                           prompts);
  }
};

struct UserAuthInfoResponseMsg : Msg<SshMessageType::UserAuthInfoResponse> {
  field<string_list, LengthPrefixed | ListSizePrefixed> responses;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size, responses);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer, responses);
  }
};

struct UserAuthBannerMsg : Msg<SshMessageType::UserAuthBanner> {
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           message,
                           language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           message,
                           language_tag);
  }
};

struct UserAuthFailureMsg : Msg<SshMessageType::UserAuthFailure> {
  field<string_list, NameListFormat> methods;
  field<bool> partial;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size, methods, partial);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer, methods, partial);
  }
};

struct DisconnectMsg : Msg<SshMessageType::Disconnect> {
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg<type>(buffer, payload_size,
                           reason_code,
                           description,
                           language_tag);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
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
    return decodeMsg<type>(buffer, payload_size,
                           public_key_alg,
                           public_key);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg<type>(buffer,
                           public_key_alg,
                           public_key);
  }
};

struct AnyMsg : SshMsg {
  field<SshMessageType> msgtype;
  field<bytes> raw_packet; // includes msg_type

  SshMessageType msg_type() const override { return msgtype; }

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    peekType(buffer, &msgtype);
    return raw_packet.decode(buffer, payload_size);
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return raw_packet.encode(buffer);
  }

  absl::StatusOr<SshMsgPtr> unwrap() const {
    auto mp = SshMsgPtr([mt = msg_type()]() -> SshMsg* {
      switch (mt) {
      case SshMessageType::Disconnect:              return new DisconnectMsg;
      case SshMessageType::Ignore:                  return new IgnoreMsg;
      case SshMessageType::Unimplemented:           return new UnimplementedMsg;
      case SshMessageType::Debug:                   return new DebugMsg;
      case SshMessageType::ServiceRequest:          return new ServiceRequestMsg;
      case SshMessageType::ServiceAccept:           return new ServiceAcceptMsg;
      case SshMessageType::KexInit:                 return new KexInitMessage;
      case SshMessageType::KexECDHInit:             return new KexEcdhInitMessage;
      case SshMessageType::KexECDHReply:            return new KexEcdhReplyMsg;
      case SshMessageType::NewKeys:                 return new NewKeysMsg;
      case SshMessageType::UserAuthRequest:         return new UserAuthRequestMsg;
      case SshMessageType::UserAuthFailure:         return new UserAuthFailureMsg;
      case SshMessageType::UserAuthSuccess:         return new UserAuthSuccessMsg;
      case SshMessageType::UserAuthBanner:          return new UserAuthBannerMsg;
      case SshMessageType::UserAuthPubKeyOk:        return new UserAuthPubKeyOkMsg;
      case SshMessageType::UserAuthInfoResponse:    return new UserAuthInfoResponseMsg;
      case SshMessageType::GlobalRequest:           return new GlobalRequestMsg;
      case SshMessageType::RequestSuccess:          return new GlobalRequestSuccessMsg;
      case SshMessageType::RequestFailure:          return new GlobalRequestFailureMsg;
      case SshMessageType::ChannelOpen:             return new ChannelOpenMsg;
      case SshMessageType::ChannelOpenConfirmation: return new ChannelOpenConfirmationMsg;
      case SshMessageType::ChannelOpenFailure:      return new ChannelOpenFailureMsg;
      case SshMessageType::ChannelWindowAdjust:     return new ChannelWindowAdjustMsg;
      case SshMessageType::ChannelData:             return new ChannelDataMsg;
      case SshMessageType::ChannelExtendedData:     return new ChannelExtendedDataMsg;
      case SshMessageType::ChannelEOF:              return new ChannelEOFMsg;
      case SshMessageType::ChannelClose:            return new ChannelCloseMsg;
      case SshMessageType::ChannelRequest:          return new ChannelRequestMsg;
      case SshMessageType::ChannelSuccess:          return new ChannelSuccessMsg;
      case SshMessageType::ChannelFailure:          return new ChannelFailureMsg;
      default:                                      PANIC("unimplemented");
      }
    }());

    auto stat = with_buffer_view(*raw_packet, [&mp](Envoy::Buffer::Instance& buffer) {
      return mp->decode(buffer, buffer.length());
    });
    if (!stat.ok()) {
      return stat.status();
    }
    return mp;
  }

  static absl::StatusOr<AnyMsg> wrap(SshMsg&& msg) {
    AnyMsg m;
    Envoy::Buffer::OwnedImpl tmp;
    if (auto stat = msg.encode(tmp); !stat.ok()) {
      return stat.status();
    }
    AnyMsg::peekType(tmp, &m.msgtype);
    m.raw_packet = flushTo<bytes>(tmp);
    return m;
  }

  static absl::StatusOr<AnyMsg> fromString(std::string_view str) {
    AnyMsg m{};
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
