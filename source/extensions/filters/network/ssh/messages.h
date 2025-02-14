#pragma once

#include <cstdint>
#include <type_traits>
#include <string>
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "openssl/rand.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum class SshMessageType : uint8_t {
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

inline auto format_as(SshMessageType mt) { return fmt::underlying(mt); }

constexpr inline SshMessageType operator~(SshMessageType t) {
  return static_cast<SshMessageType>(~static_cast<uint8_t>(t));
}
constexpr inline SshMessageType operator|(SshMessageType l, SshMessageType r) {
  return static_cast<SshMessageType>(static_cast<uint8_t>(l) | static_cast<uint8_t>(r));
}

static constexpr auto kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org";
static constexpr auto kexAlgoCurve25519SHA256 = "curve25519-sha256";

static const NameList preferredKexAlgos = {kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH};

static constexpr auto cipherAES128GCM = "aes128-gcm@openssh.com";
static constexpr auto cipherAES256GCM = "aes256-gcm@openssh.com";
static constexpr auto cipherChacha20Poly1305 = "chacha20-poly1305@openssh.com";

static const NameList preferredCiphers = {cipherChacha20Poly1305, cipherAES128GCM, cipherAES256GCM};

// TODO: non-AEAD cipher support
static const NameList supportedMACs{
    // "hmac-sha2-256-etm@openssh.com",
    // "hmac-sha2-512-etm@openssh.com",
    // "hmac-sha2-256",
    // "hmac-sha2-512",
    // "hmac-sha1",
    // "hmac-sha1-96",
};

template <typename T>
std::enable_if_t<std::is_integral_v<T>, size_t> read(Envoy::Buffer::Instance& buffer, T& out) {
  if (buffer.length() < sizeof(T)) {
    throw EnvoyException("short read");
  }
  out = buffer.drainBEInt<T>();
  return sizeof(T);
}

template <typename T>
std::enable_if_t<std::is_integral_v<T>, size_t> write(Envoy::Buffer::Instance& buffer, T t) {
  buffer.writeBEInt(t);
  return sizeof(T);
}

template <> inline size_t read<bool>(Envoy::Buffer::Instance& buffer, bool& out) {
  uint8_t b{};
  auto n = read(buffer, b);
  out = (b != 0);
  return n;
}

template <> inline size_t write<bool>(Envoy::Buffer::Instance& buffer, bool b) {
  buffer.writeByte(static_cast<uint8_t>(b));
  return 1;
}

inline size_t readBytes(Envoy::Buffer::Instance& buffer, bytearray& out) {
  auto sz = out.size();
  buffer.copyOut(0, sz, out.data());
  buffer.drain(sz);
  return sz;
}

inline size_t readBytes(Envoy::Buffer::Instance& buffer, bytearray& out, size_t n) {
  if (buffer.length() < n) {
    throw EnvoyException("short read");
  }
  out.clear();
  out.resize(n);
  if (n > 0) {
    buffer.copyOut(0, n, out.data());
    buffer.drain(n);
  }
  return n;
}

inline size_t writeBytes(Envoy::Buffer::Instance& buffer, const bytearray& bytes) {
  auto sz = bytes.size();
  buffer.add(bytes.data(), sz);
  return sz;
}

template <size_t N> inline size_t readFixedBytes(Envoy::Buffer::Instance& buffer, void* out) {
  if (buffer.length() < N) {
    throw EnvoyException("short read");
  }
  buffer.copyOut(0, N, out);
  buffer.drain(N);
  return N;
}

template <size_t N> inline size_t writeFixedBytes(Envoy::Buffer::Instance& buffer, const void* in) {
  buffer.add(in, N);
  return N;
}

inline size_t readString(Envoy::Buffer::Instance& buffer, auto& out) {
  size_t n = 0;
  auto size = buffer.drainBEInt<uint32_t>();
  n += sizeof(size);
  // read up to 'size' bytes
  if (buffer.length() < size) {
    // invalid
    throw EnvoyException("short read");
  }
  out.clear();
  out.resize(size);
  buffer.copyOut(0, size, out.data());
  n += size;
  buffer.drain(size);
  return n;
}

inline size_t writeString(Envoy::Buffer::Instance& buffer, const auto& str) {
  size_t n = 0;
  uint32_t sz = str.size();
  buffer.writeBEInt(sz);
  n += sizeof(sz);
  buffer.add(str.data(), str.size());
  n += str.size();
  return n;
}

inline size_t writeString(Envoy::Buffer::Instance& buffer, const char* str) {
  return writeString(buffer, std::string_view(str));
}

void copyWithLengthPrefix(auto& dst, const auto& src) {
  uint32_t len = htonl(static_cast<uint32_t>(src.size()));
  dst.clear();
  dst.resize(src.size() + sizeof(len));

  memcpy(dst.data() + sizeof(len), src.data(), src.size());
  memcpy(dst.data(), reinterpret_cast<void*>(&len), sizeof(len));
}

void copyWithLengthPrefix(auto& dst, const auto* src, size_t size) {
  uint32_t len = htonl(static_cast<uint32_t>(size));
  dst.clear();
  dst.resize(size + sizeof(len));
  memcpy(dst.data() + sizeof(len), src, size);
  memcpy(dst.data(), reinterpret_cast<void*>(&len), sizeof(len));
}

void copyWithLengthPrefixAndType(auto& dst, uint8_t type, const auto& src) {
  uint32_t len = htonl(src.size() + 1); // NB add 1 to len
  dst.clear();
  dst.resize(src.size() + sizeof(len) + 1);
  memcpy(dst.data() + sizeof(len) + 1, src.data(), src.size());
  memcpy(dst.data(), reinterpret_cast<void*>(&len), sizeof(len));
  dst[4] = type;
}

inline size_t readNameList(Envoy::Buffer::Instance& buffer, NameList& out) {
  size_t n = 0;
  auto size = buffer.drainBEInt<uint32_t>();
  n += sizeof(size);
  if (buffer.length() < size) {
    throw EnvoyException("short read");
  }
  std::string current;
  for (size_t i = 0; i < size; i++) {
    auto c = buffer.drainInt<char>();
    n++;
    if (c == ',') {
      if (current.length() > 0) {
        out.push_back(std::move(current));
        current.clear();
      }
      continue;
    }
    current += c;
  }
  if (current.length() > 0) {
    out.push_back(std::move(current));
  }
  return n;
}

inline size_t writeNameList(Envoy::Buffer::Instance& buffer, const NameList& list) {
  uint32_t size = 0;
  for (const auto& entry : list) {
    size += entry.length();
  }
  if (list.size() > 0) {
    size += list.size() - 1; // commas
  }
  buffer.writeBEInt(size);

  for (size_t i = 0; i < list.size(); i++) {
    buffer.add(list[i]);
    if (i < list.size() - 1) {
      buffer.writeByte(',');
    }
  }
  return sizeof(size) + size;
}

// equivalent to sshbuf_put_bignum2_bytes
inline void writeBignum(Envoy::Buffer::Instance& buffer, const uint8_t* src, size_t srclen) {
  std::basic_string_view str{src, srclen};
  // skip leading zeros
  str = str.substr(str.find_first_not_of(static_cast<uint8_t>(0)));
  size_t len = str.length();
  // prepend a zero byte if the most significant bit is set
  auto prepend = (len > 0 && (str[0] & 0x80) != 0);
  buffer.writeBEInt<uint32_t>(prepend ? (len + 1) : len);
  if (prepend) {
    buffer.writeByte(0);
  }
  buffer.add(str.data(), str.length());
}

struct BaseSshMsg {
  virtual ~BaseSshMsg() = default;
  virtual SshMessageType msg_type() const PURE;
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
  virtual size_t readExtra(Envoy::Buffer::Instance& buffer, bytearray& out, size_t len) {
    return readBytes(buffer, out, len);
  }
  virtual size_t writeExtra(Envoy::Buffer::Instance& buffer, const bytearray& in) const {
    return writeBytes(buffer, in);
  }
  static void peekType(Envoy::Buffer::Instance& buffer, SshMessageType* out) {
    *out = buffer.peekInt<SshMessageType>();
  }

  static size_t readType(Envoy::Buffer::Instance& buffer, SshMessageType* out) {
    *out = buffer.drainInt<SshMessageType>();
    return 1;
  }

  template <SshMessageType MT> static size_t readType(Envoy::Buffer::Instance& buffer) {
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != MT) {
      throw EnvoyException("unexpected message type");
    }
    return 1;
  }

  static size_t writeType(Envoy::Buffer::Instance& buffer, SshMessageType t) {
    buffer.writeByte(t);
    return 1;
  }

  template <SshMessageType MT> static size_t writeType(Envoy::Buffer::Instance& buffer) {
    buffer.writeByte(MT);
    return 1;
  }
};

template <SshMessageType MT> struct MsgType : public virtual BaseSshMsg {
  static constexpr SshMessageType type = MT;

  SshMessageType msg_type() const override { return type; }
};

template <typename T> absl::StatusOr<T> readPacket(Envoy::Buffer::Instance& buffer) noexcept {
  try {
    size_t n = 0;
    uint32_t packet_length{};
    uint8_t padding_length{};
    n += read<uint32_t>(buffer, packet_length);
    n += read<uint8_t>(buffer, padding_length);
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
    bytearray padding(padding_length);
    n += readBytes(buffer, padding);
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
  n += write<uint32_t>(out, packet_length);
  n += write<uint8_t>(out, padding_length);
  out.move(payloadBytes);
  n += payload_length;

  bytearray padding(padding_length, 0);
  RAND_bytes(padding.data(), padding.size());
  n += writeBytes(out, padding);
  return n;
}

struct KexInitMessage : SshMsg, MsgType<SshMessageType::KexInit> {
  uint8_t cookie[16];
  NameList kex_algorithms;
  NameList server_host_key_algorithms;
  NameList encryption_algorithms_client_to_server;
  NameList encryption_algorithms_server_to_client;
  NameList mac_algorithms_client_to_server;
  NameList mac_algorithms_server_to_client;
  NameList compression_algorithms_client_to_server;
  NameList compression_algorithms_server_to_client;
  NameList languages_client_to_server;
  NameList languages_server_to_client;
  uint8_t first_kex_packet_follows;
  uint32_t reserved;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readFixedBytes<sizeof(cookie)>(buffer, cookie);
    n += readNameList(buffer, kex_algorithms);
    n += readNameList(buffer, server_host_key_algorithms);
    n += readNameList(buffer, encryption_algorithms_client_to_server);
    n += readNameList(buffer, encryption_algorithms_server_to_client);
    n += readNameList(buffer, mac_algorithms_client_to_server);
    n += readNameList(buffer, mac_algorithms_server_to_client);
    n += readNameList(buffer, compression_algorithms_client_to_server);
    n += readNameList(buffer, compression_algorithms_server_to_client);
    n += readNameList(buffer, languages_client_to_server);
    n += readNameList(buffer, languages_server_to_client);
    n += read(buffer, first_kex_packet_follows);
    n += read(buffer, reserved);
    return n;
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeFixedBytes<sizeof(cookie)>(buffer, cookie);
    n += writeNameList(buffer, kex_algorithms);
    n += writeNameList(buffer, server_host_key_algorithms);
    n += writeNameList(buffer, encryption_algorithms_client_to_server);
    n += writeNameList(buffer, encryption_algorithms_server_to_client);
    n += writeNameList(buffer, mac_algorithms_client_to_server);
    n += writeNameList(buffer, mac_algorithms_server_to_client);
    n += writeNameList(buffer, compression_algorithms_client_to_server);
    n += writeNameList(buffer, compression_algorithms_server_to_client);
    n += writeNameList(buffer, languages_client_to_server);
    n += writeNameList(buffer, languages_server_to_client);
    n += write(buffer, first_kex_packet_follows);
    n += write(buffer, reserved);
    return n;
  }
};

struct KexEcdhInitMessage : SshMsg, MsgType<SshMessageType::KexECDHInit> {
  bytearray client_pub_key;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, client_pub_key);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, client_pub_key);
    return n;
  }
};

struct KexEcdhReplyMsg : SshMsg, MsgType<SshMessageType::KexECDHReply> {
  bytearray host_key;
  bytearray ephemeral_pub_key;
  bytearray signature;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, host_key);
    n += readString(buffer, ephemeral_pub_key);
    n += readString(buffer, signature);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, host_key);
    n += writeString(buffer, ephemeral_pub_key);
    n += writeString(buffer, signature);
    return n;
  }
};

struct ServiceRequestMsg : SshMsg, MsgType<SshMessageType::ServiceRequest> {
  std::string service_name;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, service_name);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, service_name);
    return n;
  }
};

struct ServiceAcceptMsg : SshMsg, MsgType<SshMessageType::ServiceAccept> {
  std::string service_name;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, service_name);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, service_name);
    return n;
  }
};

template <SshMessageType T> struct EmptyMsg : SshMsg, MsgType<T> {
  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override { return readType<T>(buffer); }
  size_t encode(Envoy::Buffer::Instance& buffer) const override { return writeType<T>(buffer); }
};

struct ChannelOpenMsg : SshMsg, MsgType<SshMessageType::ChannelOpen> {
  std::string channel_type;
  uint32_t sender_channel;
  uint32_t initial_window_size;
  uint32_t max_packet_size;
  bytearray extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, channel_type);
    n += read(buffer, sender_channel);
    n += read(buffer, initial_window_size);
    n += read(buffer, max_packet_size);
    n += readExtra(buffer, extra, payload_size - n);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, channel_type);
    n += write(buffer, sender_channel);
    n += write(buffer, initial_window_size);
    n += write(buffer, max_packet_size);
    n += writeExtra(buffer, extra);
    return n;
  }
};

struct ChannelRequestMsg : SshMsg, MsgType<SshMessageType::ChannelRequest> {
  uint32_t channel;
  std::string request_type;
  bool want_reply;
  bytearray extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, channel);
    n += readString(buffer, request_type);
    n += read(buffer, want_reply);
    n += readExtra(buffer, extra, payload_size - n);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, channel);
    n += writeString(buffer, request_type);
    n += write(buffer, want_reply);
    n += writeExtra(buffer, extra);
    return n;
  }
};

struct ChannelOpenConfirmationMsg : SshMsg, MsgType<SshMessageType::ChannelOpenConfirmation> {
  uint32_t recipient_channel;
  uint32_t sender_channel;
  uint32_t initial_window_size;
  uint32_t max_packet_size;
  bytearray extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    n += read(buffer, sender_channel);
    n += read(buffer, initial_window_size);
    n += read(buffer, max_packet_size);
    n += readExtra(buffer, extra, payload_size - n);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    n += write(buffer, sender_channel);
    n += write(buffer, initial_window_size);
    n += write(buffer, max_packet_size);
    n += writeExtra(buffer, extra);
    return n;
  }
};

struct ChannelOpenFailureMsg : SshMsg, MsgType<SshMessageType::ChannelOpenFailure> {
  uint32_t recipient_channel;
  uint32_t reason_code;
  std::string description;
  std::string language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    n += read(buffer, reason_code);
    n += readString(buffer, description);
    n += readString(buffer, language_tag);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    n += write(buffer, reason_code);
    n += writeString(buffer, description);
    n += writeString(buffer, language_tag);
    return n;
  }
};

struct ChannelWindowAdjustMsg : SshMsg, MsgType<SshMessageType::ChannelWindowAdjust> {
  uint32_t recipient_channel;
  uint32_t bytes_to_add;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    n += read(buffer, bytes_to_add);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    n += write(buffer, bytes_to_add);
    return n;
  }
};

struct ChannelDataMsg : SshMsg, MsgType<SshMessageType::ChannelData> {
  uint32_t recipient_channel;
  bytearray data;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    n += readString(buffer, data);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    n += writeString(buffer, data);
    return n;
  }
};

struct ChannelExtendedDataMsg : SshMsg, MsgType<SshMessageType::ChannelExtendedData> {
  uint32_t recipient_channel;
  uint32_t data_type_code;
  bytearray data;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    n += read(buffer, data_type_code);
    n += readString(buffer, data);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    n += write(buffer, data_type_code);
    n += writeString(buffer, data);
    return n;
  }
};

struct ChannelEOFMsg : SshMsg, MsgType<SshMessageType::ChannelEOF> {
  uint32_t recipient_channel;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    return n;
  }
};

struct ChannelCloseMsg : SshMsg, MsgType<SshMessageType::ChannelClose> {
  uint32_t recipient_channel;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    return n;
  }
};

struct ChannelSuccessMsg : SshMsg, MsgType<SshMessageType::ChannelSuccess> {
  uint32_t recipient_channel;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    return n;
  }
};

struct ChannelFailureMsg : SshMsg, MsgType<SshMessageType::ChannelFailure> {
  uint32_t recipient_channel;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, recipient_channel);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, recipient_channel);
    return n;
  }
};

struct GlobalRequestMsg : SshMsg, MsgType<SshMessageType::GlobalRequest> {
  std::string request_name;
  bool want_reply;
  bytearray extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, request_name);
    n += read(buffer, want_reply);
    n += readExtra(buffer, extra, payload_size - n);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, request_name);
    n += write(buffer, want_reply);
    n += writeExtra(buffer, extra);
    return n;
  }
};

struct HostKeysProveRequestMsg : GlobalRequestMsg {
  std::vector<bytearray> hostkeys;

  size_t readExtra(Envoy::Buffer::Instance& buffer, bytearray&, size_t len) override {
    size_t n = 0;
    while (len > 0) {
      bytearray b;
      n += readString(buffer, b);
      hostkeys.push_back(std::move(b));
    }
    return n;
  }
  size_t writeExtra(Envoy::Buffer::Instance& buffer, const bytearray&) const override {
    size_t n = 0;
    for (const auto& b : hostkeys) {
      n += writeString(buffer, b);
    }
    return n;
  }
};

struct GlobalRequestSuccessMsg : SshMsg, MsgType<SshMessageType::RequestSuccess> {
  bytearray extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += readExtra(buffer, extra, payload_size - n);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeExtra(buffer, extra);
    return n;
  }
};

struct HostKeysProveResponseMsg : GlobalRequestSuccessMsg {
  std::vector<bytearray> signatures;

  size_t readExtra(Envoy::Buffer::Instance& buffer, bytearray&, size_t len) override {
    size_t n = 0;
    while (len > 0) {
      bytearray b;
      n += readString(buffer, b);
      signatures.push_back(std::move(b));
    }
    return n;
  }
  size_t writeExtra(Envoy::Buffer::Instance& buffer, const bytearray&) const override {
    size_t n = 0;
    for (const auto& b : signatures) {
      n += writeString(buffer, b);
    }
    return n;
  }
};

struct GlobalRequestFailureMsg : EmptyMsg<SshMessageType::RequestFailure> {};

struct IgnoreMsg : SshMsg, MsgType<SshMessageType::Ignore> {
  bytearray data;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, data);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, data);
    return n;
  }
};

struct DebugMsg : SshMsg, MsgType<SshMessageType::Debug> {
  bool always_display;
  std::string message;
  std::string language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, always_display);
    n += readString(buffer, message);
    n += readString(buffer, language_tag);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, always_display);
    n += writeString(buffer, message);
    n += writeString(buffer, language_tag);

    return n;
  }
};

struct UnimplementedMsg : SshMsg, MsgType<SshMessageType::Unimplemented> {
  // FIXME: the sequence numbers in this message are likely going to be wrong, need to adjust them
  uint32_t sequence_number;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, sequence_number);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, sequence_number);
    return n;
  }
};

struct UserAuthRequestMsg : SshMsg, MsgType<SshMessageType::UserAuthRequest> {
  std::string username;
  std::string service_name;
  std::string method_name;
  bytearray extra;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, username);
    n += readString(buffer, service_name);
    n += readString(buffer, method_name);
    n += readExtra(buffer, extra, payload_size - n);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, username);
    n += writeString(buffer, service_name);
    n += writeString(buffer, method_name);
    n += writeExtra(buffer, extra);
    return n;
  }
};

struct PubKeyUserAuthRequestMsg : UserAuthRequestMsg {
  bool has_signature;
  std::string public_key_alg;
  bytearray public_key;
  bytearray signature;

  size_t readExtra(Envoy::Buffer::Instance& buffer, bytearray& out, size_t len) override {
    size_t n = read(buffer, has_signature);
    n += readString(buffer, public_key_alg);
    n += readString(buffer, public_key);
    if (has_signature) {
      n += readString(buffer, signature);
    }
    n += UserAuthRequestMsg::readExtra(buffer, out, len - n);
    return n;
  }
  size_t writeExtra(Envoy::Buffer::Instance& buffer, const bytearray&) const override {
    size_t n = write(buffer, has_signature);
    n += writeString(buffer, public_key_alg);
    n += writeString(buffer, public_key);
    // This check is important; even if signature was empty, writeString would still append a
    // 4-byte length field containing 0. We also can't check based on has_signature, because
    // the signature is computed over the wire encoding of this message and requires has_signature
    // to be true (see RFC4252 sec. 7)
    if (!signature.empty()) {
      n += writeString(buffer, signature);
    }
    return n;
  }
};

struct KeyboardInteractiveUserAuthRequestMsg : UserAuthRequestMsg {
  std::string language_tag;
  NameList submethods;

  size_t readExtra(Envoy::Buffer::Instance& buffer, bytearray& out, size_t len) override {
    size_t n = readString(buffer, language_tag);
    n += readNameList(buffer, submethods);
    n += UserAuthRequestMsg::readExtra(buffer, out, len - n);
    return n;
  }
  size_t writeExtra(Envoy::Buffer::Instance& buffer, const bytearray&) const override {
    size_t n = writeString(buffer, language_tag);
    n += writeNameList(buffer, submethods);
    return n;
  }
};

struct UserAuthInfoRequestMsg : SshMsg, MsgType<SshMessageType::UserAuthInfoRequest> {
  struct prompt {
    std::string prompt;
    bool echo;
  };

  std::string name;
  std::string instruction;
  std::string language_tag;
  int32_t num_prompts;
  std::vector<prompt> prompts;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, name);
    n += readString(buffer, instruction);
    n += readString(buffer, language_tag);
    n += read(buffer, num_prompts);
    for (int32_t i = 0; i < num_prompts && n < payload_size; i++) {
      prompt p;
      n += readString(buffer, p.prompt);
      n += read(buffer, p.echo);
      prompts.push_back(std::move(p));
    }
    return n;
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, name);
    n += writeString(buffer, instruction);
    n += writeString(buffer, language_tag);
    n += write(buffer, num_prompts);
    for (const auto& prompt : prompts) {
      n += writeString(buffer, prompt.prompt);
      n += write(buffer, prompt.echo);
    }
    return n;
  }
};

struct UserInfoResponseMsg : SshMsg, MsgType<SshMessageType::UserAuthInfoResponse> {
  int32_t num_responses;
  std::vector<std::string> responses;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, num_responses);
    for (int32_t i = 0; i < num_responses && n < payload_size; i++) {
      std::string response;
      n += readString(buffer, response);
      responses.push_back(std::move(response));
    }
    return n;
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, num_responses);
    for (const auto& response : responses) {
      n += writeString(buffer, response);
    }
    return n;
  }
};

struct UserAuthBannerMsg : SshMsg, MsgType<SshMessageType::UserAuthBanner> {
  std::string message;
  std::string language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readString(buffer, message);
    n += readString(buffer, language_tag);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeString(buffer, message);
    n += writeString(buffer, language_tag);
    return n;
  }
};

struct UserAuthFailureMsg : SshMsg, MsgType<SshMessageType::UserAuthFailure> {
  NameList methods;
  bool partial;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += readNameList(buffer, methods);
    n += read(buffer, partial);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += writeNameList(buffer, methods);
    n += write(buffer, partial);
    return n;
  }
};

struct DisconnectMsg : SshMsg, MsgType<SshMessageType::Disconnect> {
  uint32_t reason_code;
  std::string description;
  std::string language_tag;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    size_t n = readType<type>(buffer);
    n += read(buffer, reason_code);
    n += readString(buffer, description);
    n += readString(buffer, language_tag);
    return n;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    size_t n = writeType<type>(buffer);
    n += write(buffer, reason_code);
    n += writeString(buffer, description);
    n += writeString(buffer, language_tag);
    return n;
  }
};

struct AnyMsg : SshMsg {
  SshMessageType msgtype;
  bytearray raw_packet; // includes msg_type

  SshMessageType msg_type() const override { return msgtype; }

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    peekType(buffer, &msgtype);
    return readBytes(buffer, raw_packet, payload_size);
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.add(raw_packet.data(), raw_packet.size());
    return raw_packet.size();
  }

  template <typename T> T unwrap() const {
    T t{};
    Envoy::Buffer::OwnedImpl buf;
    buf.add(raw_packet.data(), raw_packet.size());
    t.decode(buf, buf.length());
    buf.drain(buf.length());
    return t;
  }

  static AnyMsg wrap(SshMsg&& msg) {
    AnyMsg m;
    Envoy::Buffer::OwnedImpl buf;
    msg.encode(buf);
    AnyMsg::peekType(buf, &m.msgtype);
    m.raw_packet.resize(buf.length());
    buf.copyOut(0, buf.length(), m.raw_packet.data());
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

using SshMessageDispatcher = MessageDispatcher<AnyMsg>;
using SshMessageHandler = MessageHandler<AnyMsg>;

template <> struct message_case_type<AnyMsg> : std::type_identity<SshMessageType> {};

template <> inline SshMessageType messageCase(const AnyMsg& msg) { return msg.msg_type(); }

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec