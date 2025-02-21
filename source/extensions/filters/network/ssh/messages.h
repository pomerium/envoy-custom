#pragma once

#include <cstdint>
#include <type_traits>
#include <string>

#include "openssl/rand.h"

#include "source/common/buffer/buffer_impl.h"

#include "source/extensions/filters/network/ssh/buffer.h"
#include "source/extensions/filters/network/ssh/message_handler.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

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

inline size_t read(Envoy::Buffer::Instance& buffer, SshMessageType& t, size_t) {
  t = buffer.drainInt<SshMessageType>();
  return 1;
}

inline size_t write(Envoy::Buffer::Instance& buffer, const SshMessageType& t) {
  buffer.writeByte(t);
  return 1;
}

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

inline auto format_as(SshMessageType mt) {
  return fmt::underlying(mt);
}

constexpr inline SshMessageType operator~(SshMessageType t) {
  return static_cast<SshMessageType>(~static_cast<uint8_t>(t));
}
constexpr inline SshMessageType operator|(SshMessageType l, SshMessageType r) {
  return static_cast<SshMessageType>(static_cast<uint8_t>(l) | static_cast<uint8_t>(r));
}

static constexpr auto kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org";
static constexpr auto kexAlgoCurve25519SHA256 = "curve25519-sha256";

static const string_list preferredKexAlgos = {kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH};

static constexpr auto cipherAES128GCM = "aes128-gcm@openssh.com";
static constexpr auto cipherAES256GCM = "aes256-gcm@openssh.com";
static constexpr auto cipherChacha20Poly1305 = "chacha20-poly1305@openssh.com";

static const string_list preferredCiphers = {cipherChacha20Poly1305, cipherAES128GCM, cipherAES256GCM};

// TODO: non-AEAD cipher support
static const string_list supportedMACs{
    // "hmac-sha2-256-etm@openssh.com",
    // "hmac-sha2-512-etm@openssh.com",
    // "hmac-sha2-256",
    // "hmac-sha2-512",
    // "hmac-sha1",
    // "hmac-sha1-96",
};

struct direction_t {
  bytes iv_tag;
  bytes key_tag;
  bytes mac_key_tag;
};

struct BaseSshMsg {
  virtual ~BaseSshMsg() = default;
  virtual SshMessageType msg_type() const PURE;

  virtual bool is_channel_message() const {
    return false;
  }
};

struct SshMsg : public virtual BaseSshMsg {
  virtual ~SshMsg() = default;

  virtual size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) PURE;
  virtual size_t encode(Envoy::Buffer::Instance& buffer) const PURE;

  std::string toString() const {
    Envoy::Buffer::OwnedImpl buf;
    this->encode(buf);
    auto out = buf.toString();
    buf.drain(buf.length());
    return out;
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

struct ChannelMsg : SshMsg {
  virtual field<uint32_t>& get_recipient_channel() PURE;
};

template <SshMessageType MT>
struct MsgType : public virtual BaseSshMsg {
  static constexpr SshMessageType type = MT;

  SshMessageType msg_type() const override {
    return type;
  }

  bool is_channel_message() const override {
    return is_channel_msg_v<MT>;
  }
};

template <SshMessageType T, typename = void>
struct Msg : SshMsg, MsgType<T> {};

template <SshMessageType T>
struct Msg<T, std::enable_if_t<is_channel_msg_v<T>>> : ChannelMsg, MsgType<T> {};

// TODO: is SubMsg necessary? sub-messages maybe shouldn't be usable as an SshMsg
template <SshMessageType T>
struct SubMsg : SshMsg, MsgType<T> {};

template <typename T>
absl::StatusOr<T> readPacket(Envoy::Buffer::Instance& buffer) noexcept {
  try {
    size_t n = 0;
    uint32_t packet_length{};
    uint8_t padding_length{};
    n += read(buffer, packet_length, sizeof(packet_length));
    n += read(buffer, padding_length, sizeof(padding_length));
    T payload{};
    {
      auto payload_expected_size = packet_length - padding_length - 1;
      auto payload_actual_size = payload.decode(buffer, payload_expected_size);
      if (payload_actual_size != payload_expected_size) {
        return absl::InvalidArgumentError(fmt::format(
            "unexpected packet payload size of {} bytes (expected {})", n, payload_expected_size));
      }
      n += payload_actual_size;
    }
    bytes padding(padding_length);
    n += read(buffer, padding, static_cast<size_t>(padding_length));
    return payload;
  } catch (const EnvoyException& e) {
    return absl::InternalError(fmt::format("error decoding packet: {}", e.what()));
  }
}

inline size_t writePacket(Envoy::Buffer::Instance& out, const SshMsg& msg,
                          size_t cipher_block_size = 8, size_t aad_len = 0) {
  Envoy::Buffer::OwnedImpl payloadBytes;
  size_t payload_length = msg.encode(payloadBytes);

  // RFC4253 § 6
  uint8_t padding_length = cipher_block_size - ((5 + payload_length - aad_len) % cipher_block_size);
  if (padding_length < 4) {
    padding_length += cipher_block_size;
  }
  uint32_t packet_length = sizeof(padding_length) + payload_length + padding_length;

  size_t n = 0;
  n += write(out, packet_length);
  n += write(out, padding_length);
  out.move(payloadBytes);
  n += payload_length;

  bytes padding(padding_length, 0);
  RAND_bytes(padding.data(), padding.size());
  n += write(out, padding);
  return n;
}

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

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
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

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           client_pub_key);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           client_pub_key);
  }
};

struct KexEcdhReplyMsg : Msg<SshMessageType::KexECDHReply> {
  field<bytes, LengthPrefixed> host_key;
  field<bytes, LengthPrefixed> ephemeral_pub_key;
  field<bytes, LengthPrefixed> signature;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           host_key,
                           ephemeral_pub_key,
                           signature);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           host_key,
                           ephemeral_pub_key,
                           signature);
  }
};

struct ServiceRequestMsg : Msg<SshMessageType::ServiceRequest> {
  field<std::string, LengthPrefixed> service_name;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size, service_name);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer, service_name);
  }
};

struct ServiceAcceptMsg : Msg<SshMessageType::ServiceAccept> {
  field<std::string, LengthPrefixed> service_name;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size, service_name);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer, service_name);
  }
};

template <SshMessageType T>
struct EmptyMsg : Msg<T> {
  using Msg<T>::type;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer);
  }
};

struct ChannelOpenMsg : Msg<SshMessageType::ChannelOpen> {
  field<std::string, LengthPrefixed> channel_type;
  field<uint32_t> sender_channel;
  field<uint32_t> initial_window_size;
  field<uint32_t> max_packet_size;
  field<bytes> extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = decodeMsg<type>(buffer, payload_size,
                               channel_type,
                               sender_channel,
                               initial_window_size,
                               max_packet_size,
                               extra);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = encodeMsg<type>(buffer,
                               channel_type,
                               sender_channel,
                               initial_window_size,
                               max_packet_size,
                               extra);
    return n;
  }
};

struct PtyReqChannelRequestMsg : SubMsg<SshMessageType::ChannelRequest> {
  static constexpr auto request_type = "pty-req";

  field<std::string, LengthPrefixed> term_env;
  field<uint32_t> width_columns;
  field<uint32_t> height_rows;
  field<uint32_t> width_px;
  field<uint32_t> height_px;
  field<std::string, LengthPrefixed> modes;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeFields(buffer, payload_size,
                        term_env,
                        width_columns,
                        height_rows,
                        width_px,
                        height_px,
                        modes);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeFields(buffer,
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
  sub_message<PtyReqChannelRequestMsg> msg;

  ChannelRequestMsg() {
    msg.set_key_field(&request_type);
  }

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           request_type,
                           want_reply,
                           msg);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           sender_channel,
                           initial_window_size,
                           max_packet_size,
                           extra);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           reason_code,
                           description,
                           language_tag);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           bytes_to_add);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           data);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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
  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel,
                           data_type_code,
                           data);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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
  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct ChannelCloseMsg : Msg<SshMessageType::ChannelClose> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }
  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct ChannelSuccessMsg : Msg<SshMessageType::ChannelSuccess> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct ChannelFailureMsg : Msg<SshMessageType::ChannelFailure> {
  field<uint32_t> recipient_channel;

  field<uint32_t>& get_recipient_channel() override {
    return recipient_channel;
  }
  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           recipient_channel);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           recipient_channel);
  }
};

struct HostKeysProveRequestMsg : SubMsg<SshMessageType::GlobalRequest> {
  static constexpr auto request_type = "hostkeys-prove-00@openssh.com";

  field<bytes_list, LengthPrefixed> hostkeys;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t len) override {
    return decodeFields(buffer, len, hostkeys);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeFields(buffer, hostkeys);
  }
};

struct HostKeysMsg : SubMsg<SshMessageType::GlobalRequest> {
  static constexpr auto request_type = "hostkeys-00@openssh.com";

  field<bytes_list, LengthPrefixed> hostkeys;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t len) override {
    return decodeFields(buffer, len, hostkeys);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeFields(buffer, hostkeys);
  }
};

struct GlobalRequestMsg : Msg<SshMessageType::GlobalRequest> {
  field<std::string, LengthPrefixed> request_name;
  field<bool> want_reply;
  sub_message<HostKeysProveRequestMsg, HostKeysMsg> msg;

  GlobalRequestMsg() {
    msg.set_key_field(&request_name);
  }

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           request_name,
                           want_reply,
                           msg);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           request_name,
                           want_reply,
                           msg);
  }
};

struct HostKeysProveResponseMsg : SubMsg<SshMessageType::RequestSuccess> {
  static constexpr auto request_type = "hostkeys-prove00@openssh.com";

  field<bytes_list, LengthPrefixed> signatures;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t len) override {
    return decodeFields(buffer, len, signatures);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeFields(buffer, signatures);
  };
};

struct GlobalRequestSuccessMsg : Msg<SshMessageType::RequestSuccess> {
  sub_message<HostKeysProveResponseMsg> msg;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           msg);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           msg);
  }
};

struct GlobalRequestFailureMsg : EmptyMsg<SshMessageType::RequestFailure> {};

struct IgnoreMsg : Msg<SshMessageType::Ignore> {
  field<bytes, LengthPrefixed> data;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           data);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           data);
  }
};

struct DebugMsg : Msg<SshMessageType::Debug> {
  field<bool> always_display;
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           always_display,
                           message,
                           language_tag);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           always_display,
                           message,
                           language_tag);
  }
};

struct UnimplementedMsg : Msg<SshMessageType::Unimplemented> {
  // FIXME: the sequence numbers in this message are likely going to be wrong, need to adjust them
  field<uint32_t> sequence_number;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           sequence_number);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           sequence_number);
  }
};

struct PubKeyUserAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest> {
  static constexpr auto request_type = "publickey";

  field<bool> has_signature;
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;
  field<bytes, LengthPrefixed | Conditional> signature;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeFields(buffer, payload_size,
                        has_signature,
                        public_key_alg,
                        public_key,
                        signature.enable_if(has_signature));
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    // The check on signature here is important; even if signature was empty, writeString would
    // still append a 4-byte length field containing 0. We also can't check based on has_signature,
    // because the signature is computed over the wire encoding of this message and requires
    // has_signature to be true (see RFC4252 sec. 7)
    return encodeFields(buffer,
                        has_signature,
                        public_key_alg,
                        public_key,
                        signature.enable_if(!signature->empty()));
  }
};

struct KeyboardInteractiveUserAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest> {
  static constexpr auto request_type = "keyboard-interactive";

  field<std::string, LengthPrefixed> language_tag;
  field<string_list, NameListFormat> submethods;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeFields(buffer, payload_size,
                        language_tag,
                        submethods);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeFields(buffer,
                        language_tag,
                        submethods);
  }
};

struct NoneAuthRequestMsg : SubMsg<SshMessageType::UserAuthRequest> {
  static constexpr auto request_type = "none";

  size_t decode(Envoy::Buffer::Instance&, size_t) override {
    return 0;
  }
  size_t encode(Envoy::Buffer::Instance&) const override {
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
      msg;

  UserAuthRequestMsg() {
    msg.set_key_field(&method_name);
  }
  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           username,
                           service_name,
                           method_name,
                           msg);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
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
  return decodeFields(buffer, payload_size, prompt.prompt, prompt.echo);
}

// implements Writer
inline size_t write(Envoy::Buffer::Instance& buffer, const userAuthInfoPrompt& prompt) {
  return encodeFields(buffer, prompt.prompt, prompt.echo);
}

struct UserAuthInfoRequestMsg : Msg<SshMessageType::UserAuthInfoRequest> {

  field<std::string, LengthPrefixed> name;
  field<std::string, LengthPrefixed> instruction;
  field<std::string, LengthPrefixed> language_tag;
  field<std::vector<userAuthInfoPrompt>, ListSizePrefixed> prompts;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           name,
                           instruction,
                           language_tag,
                           prompts);
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           name,
                           instruction,
                           language_tag,
                           prompts);
  }
};

struct UserAuthInfoResponseMsg : Msg<SshMessageType::UserAuthInfoResponse> {
  field<string_list, LengthPrefixed | ListSizePrefixed> responses;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size, responses);
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer, responses);
  }
};

struct UserAuthBannerMsg : Msg<SshMessageType::UserAuthBanner> {
  field<std::string, LengthPrefixed> message;
  field<std::string, LengthPrefixed> language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           message,
                           language_tag);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           message,
                           language_tag);
  }
};

struct UserAuthFailureMsg : Msg<SshMessageType::UserAuthFailure> {
  field<string_list, NameListFormat> methods;
  field<bool> partial;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size, methods, partial);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer, methods, partial);
  }
};

struct DisconnectMsg : Msg<SshMessageType::Disconnect> {
  field<uint32_t> reason_code;
  field<std::string, LengthPrefixed> description;
  field<std::string, LengthPrefixed> language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           reason_code,
                           description,
                           language_tag);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           reason_code,
                           description,
                           language_tag);
  }
};

struct UserAuthSuccessMsg : EmptyMsg<SshMessageType::UserAuthSuccess> {};

struct UserAuthPubKeyOkMsg : Msg<SshMessageType::UserAuthPubKeyOk> {
  field<std::string, LengthPrefixed> public_key_alg;
  field<bytes, LengthPrefixed> public_key;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    return decodeMsg<type>(buffer, payload_size,
                           public_key_alg,
                           public_key);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return encodeMsg<type>(buffer,
                           public_key_alg,
                           public_key);
  }
};

struct AnyMsg : SshMsg {
  field<SshMessageType> msgtype;
  field<bytes> raw_packet; // includes msg_type

  SshMessageType msg_type() const override {
    return msgtype;
  }

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    peekType(buffer, &msgtype);
    return raw_packet.decode(buffer, payload_size);
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    return raw_packet.encode(buffer);
  }

  std::unique_ptr<SshMsg> unwrap() const {
    SshMsg* mp;
    switch (msg_type()) {
    case SshMessageType::Disconnect:
      mp = new DisconnectMsg;
      break;
    case SshMessageType::Ignore:
      mp = new IgnoreMsg;
      break;
    case SshMessageType::Unimplemented:
      mp = new UnimplementedMsg;
      break;
    case SshMessageType::Debug:
      mp = new DebugMsg;
      break;
    case SshMessageType::ServiceRequest:
      mp = new ServiceRequestMsg;
      break;
    case SshMessageType::ServiceAccept:
      mp = new ServiceAcceptMsg;
      break;
    case SshMessageType::KexInit:
      mp = new KexInitMessage;
      break;
    case SshMessageType::KexECDHInit:
      mp = new KexEcdhInitMessage;
      break;
    case SshMessageType::KexECDHReply:
      mp = new KexEcdhReplyMsg;
      break;
    case SshMessageType::NewKeys:
      mp = new EmptyMsg<SshMessageType::NewKeys>;
      break;
    case SshMessageType::UserAuthRequest:
      mp = new UserAuthRequestMsg;
      break;
    case SshMessageType::UserAuthFailure:
      mp = new UserAuthFailureMsg;
      break;
    case SshMessageType::UserAuthSuccess:
      mp = new UserAuthSuccessMsg;
      break;
    case SshMessageType::UserAuthBanner:
      mp = new UserAuthBannerMsg;
      break;
    case SshMessageType::UserAuthPubKeyOk:
      mp = new UserAuthPubKeyOkMsg;
      break;
    case SshMessageType::UserAuthInfoResponse:
      mp = new UserAuthInfoResponseMsg;
      break;
    case SshMessageType::GlobalRequest:
      mp = new GlobalRequestMsg;
      break;
    case SshMessageType::RequestSuccess:
      mp = new GlobalRequestSuccessMsg;
      break;
    case SshMessageType::RequestFailure:
      mp = new GlobalRequestFailureMsg;
      break;
    case SshMessageType::ChannelOpen:
      mp = new ChannelOpenMsg;
      break;
    case SshMessageType::ChannelOpenConfirmation:
      mp = new ChannelOpenConfirmationMsg;
      break;
    case SshMessageType::ChannelOpenFailure:
      mp = new ChannelOpenFailureMsg;
      break;
    case SshMessageType::ChannelWindowAdjust:
      mp = new ChannelWindowAdjustMsg;
      break;
    case SshMessageType::ChannelData:
      mp = new ChannelDataMsg;
      break;
    case SshMessageType::ChannelExtendedData:
      mp = new ChannelExtendedDataMsg;
      break;
    case SshMessageType::ChannelEOF:
      mp = new ChannelEOFMsg;
      break;
    case SshMessageType::ChannelClose:
      mp = new ChannelCloseMsg;
      break;
    case SshMessageType::ChannelRequest:
      mp = new ChannelRequestMsg;
      break;
    case SshMessageType::ChannelSuccess:
      mp = new ChannelSuccessMsg;
      break;
    case SshMessageType::ChannelFailure:
      mp = new ChannelFailureMsg;
      break;
    default:
      PANIC("unimplemented");
    }
    Envoy::Buffer::OwnedImpl buf;
    buf.add(raw_packet->data(), raw_packet->size());
    mp->decode(buf, buf.length());
    return std::unique_ptr<SshMsg>(mp);
  }

  static AnyMsg wrap(SshMsg&& msg) {
    AnyMsg m;
    Envoy::Buffer::OwnedImpl buf;
    msg.encode(buf);
    AnyMsg::peekType(buf, &m.msgtype);
    m.raw_packet->resize(buf.length());
    buf.copyOut(0, buf.length(), m.raw_packet->data());
    buf.drain(buf.length());
    return m;
  }

  static AnyMsg fromString(std::string_view str) {
    Envoy::Buffer::OwnedImpl buf;
    buf.add(str);
    AnyMsg m{};
    m.decode(buf, buf.length());
    return m;
  }
};

using SshMessageDispatcher = MessageDispatcher<SshMsg>;
using SshMessageHandler = MessageHandler<SshMsg>;
using SshMessageMiddleware = MessageMiddleware<SshMsg>;

template <>
struct message_case_type<SshMsg> : std::type_identity<SshMessageType> {};

template <>
inline SshMessageType messageCase(const SshMsg& msg) {
  return msg.msg_type();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec