#pragma once

#include <cstdint>
#include <type_traits>
#include <string>
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/ssh/util.h"
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

constexpr inline SshMessageType operator~(SshMessageType t) {
  return static_cast<SshMessageType>(~static_cast<uint8_t>(t));
}
constexpr inline SshMessageType operator|(SshMessageType l, SshMessageType r) {
  return static_cast<SshMessageType>(static_cast<uint8_t>(l) | static_cast<uint8_t>(r));
}

static constexpr auto kexAlgoECDH256 = "ecdh-sha2-nistp256";
static constexpr auto kexAlgoECDH384 = "ecdh-sha2-nistp384";
static constexpr auto kexAlgoECDH521 = "ecdh-sha2-nistp521";
static constexpr auto kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org";
static constexpr auto kexAlgoCurve25519SHA256 = "curve25519-sha256";

static const NameList preferredKexAlgos = {kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH,
                                           kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521};

static constexpr auto cipherAES128GCM = "aes128-gcm@openssh.com";
static constexpr auto cipherAES256GCM = "aes256-gcm@openssh.com";
static constexpr auto cipherChacha20Poly1305 = "chacha20-poly1305@openssh.com";

static const NameList preferredCiphers = {cipherAES128GCM, cipherAES256GCM, cipherChacha20Poly1305};

static const NameList supportedMACs{
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-sha1-96",
};

template <typename T>
std::enable_if_t<std::is_integral_v<T>, size_t> read(Envoy::Buffer::Instance& buffer, T& out) {
  if (buffer.length() < sizeof(T)) {
    throw EnvoyException("short read");
  }
  out = buffer.drainBEInt<T>();
  return sizeof(T);
}

template <> inline size_t read<bool>(Envoy::Buffer::Instance& buffer, bool& out) {
  uint8_t b{};
  auto n = read(buffer, b);
  out = (b != 0);
  return n;
}

template <typename T>
inline std::enable_if_t<sizeof(T) == 1, size_t>
readVariableBytes(Envoy::Buffer::Instance& buffer, std::basic_string<T>& out, size_t len) {
  if (buffer.length() < len) {
    throw EnvoyException("short read");
  }
  out.clear();
  out.resize(len);
  buffer.copyOut(0, len, out.data());
  buffer.drain(len);
  return len;
}

template <size_t N> inline size_t readFixedBytes(Envoy::Buffer::Instance& buffer, void* out) {
  if (buffer.length() < N) {
    throw EnvoyException("short read");
  }
  buffer.copyOut(0, N, out);
  buffer.drain(N);
  return N;
}

inline size_t readString(Envoy::Buffer::Instance& buffer, auto& out) {
  size_t nread = 0;
  auto size = buffer.drainBEInt<uint32_t>();
  nread += sizeof(size);
  // read up to 'size' bytes
  if (buffer.length() < size) {
    // invalid
    throw EnvoyException("short read");
  }
  out.clear();
  out.resize(size);
  buffer.copyOut(0, size, out.data());
  nread += size;
  buffer.drain(size);
  return nread;
}

inline size_t writeString(Envoy::Buffer::Instance& buffer, const auto& str) {
  size_t nwritten = 0;
  uint32_t sz = str.size();
  buffer.writeBEInt(sz);
  nwritten += sizeof(sz);
  buffer.add(str.data(), str.size());
  nwritten += str.size();
  return nwritten;
}

void copyWithLengthPrefix(auto& dst, const auto& src) {
  uint32_t len = htonl(static_cast<uint32_t>(src.size()));
  dst.clear();
  dst.resize(src.size() + sizeof(len));

  memcpy(dst.data() + sizeof(len), src.data(), dst.size());
  memcpy(dst.data(), reinterpret_cast<void*>(&len), sizeof(len));
}

void copyWithLengthPrefix(auto& dst, const auto* src, size_t size) {
  uint32_t len = htonl(static_cast<uint32_t>(size));
  dst.clear();
  dst.resize(size + sizeof(len));
  memcpy(dst.data() + sizeof(len), src, dst.size());
  memcpy(dst.data(), reinterpret_cast<void*>(&len), sizeof(len));
}

void copyWithLengthPrefixAndType(auto& dst, uint8_t type, const auto& src) {
  uint32_t len = htonl(src.size() + 1); // NB add 1 to len
  dst.clear();
  dst.resize(src.size() + sizeof(len) + 1);
  memcpy(dst.data() + sizeof(len) + 1, src.data(), dst.size());
  memcpy(dst.data(), reinterpret_cast<void*>(&len), sizeof(len));
  dst[4] = type;
}

inline size_t readNameList(Envoy::Buffer::Instance& buffer, NameList& out) {
  size_t nread = 0;
  auto size = buffer.drainBEInt<uint32_t>();
  nread += sizeof(size);
  if (buffer.length() < size) {
    throw EnvoyException("short read");
  }
  std::string current;
  for (size_t i = 0; i < size; i++) {
    auto c = buffer.drainInt<char>();
    nread++;
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
  return nread;
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

template <typename T, bool = std::is_trivially_move_assignable_v<T>> struct SshMsg {
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
};

template <typename T>
std::enable_if_t<std::is_base_of_v<SshMsg<T>, T>, std::tuple<T, error>>
readPacket(Envoy::Buffer::Instance& buffer) noexcept {
  try {
    auto bufferSize = buffer.length();
    size_t nread = 0;
    uint32_t packet_length{};
    uint8_t padding_length{};
    nread += read<uint32_t>(buffer, packet_length);
    nread += read<uint8_t>(buffer, padding_length);
    T payload{};
    {
      auto payload_size = packet_length - padding_length - 1;
      auto n = payload.decode(buffer, payload_size);
      nread += n;
      if (n != payload_size) {
        return {{},
                fmt::format("unexpected packet payload size of {} bytes (expected {})", nread,
                            payload_size)};
      }
    }
    std::string padding;
    nread += readVariableBytes(buffer, padding, padding_length);
    if (nread != bufferSize) {
      return {{}, fmt::format("bad packet length: {} (expected {})", bufferSize, nread)};
    }
    return {payload, std::nullopt};
  } catch (const EnvoyException& e) {
    return {{}, fmt::format("error decoding packet: {}", e.what())};
  }
}

template <typename T>
std::enable_if_t<std::is_base_of_v<SshMsg<T>, T>, size_t>
writePacket(Envoy::Buffer::Instance& out, const T& msg, size_t cipher_block_size = 8,
            size_t aad_len = 0) {
  Envoy::Buffer::OwnedImpl payloadBytes;
  size_t payload_length = msg.encode(payloadBytes);

  // RFC4253 § 6
  uint8_t padding_length = cipher_block_size - ((5 + payload_length - aad_len) % cipher_block_size);
  if (padding_length < 4) {
    padding_length += cipher_block_size;
  }
  uint32_t packet_length = sizeof(padding_length) + payload_length + padding_length;

  size_t nwritten = 0;
  out.writeBEInt<uint32_t>(packet_length);
  nwritten += sizeof(packet_length);
  out.writeByte<uint8_t>(padding_length);
  nwritten += sizeof(padding_length);
  out.move(payloadBytes);
  nwritten += payload_length;

  std::string padding(padding_length, 0);
  RAND_bytes(reinterpret_cast<uint8_t*>(padding.data()), padding.length());
  out.add(padding.data(), padding.length());
  nwritten += padding_length;
  return nwritten;
}

struct KexInitMessage : SshMsg<KexInitMessage> {
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
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != SshMessageType::KexInit) {
      throw EnvoyException("unexpected message type");
    }
    size_t nread = 1;

    nread += readFixedBytes<sizeof(cookie)>(buffer, cookie);
    nread += readNameList(buffer, kex_algorithms);
    nread += readNameList(buffer, server_host_key_algorithms);
    nread += readNameList(buffer, encryption_algorithms_client_to_server);
    nread += readNameList(buffer, encryption_algorithms_server_to_client);
    nread += readNameList(buffer, mac_algorithms_client_to_server);
    nread += readNameList(buffer, mac_algorithms_server_to_client);
    nread += readNameList(buffer, compression_algorithms_client_to_server);
    nread += readNameList(buffer, compression_algorithms_server_to_client);
    nread += readNameList(buffer, languages_client_to_server);
    nread += readNameList(buffer, languages_server_to_client);
    nread += read(buffer, first_kex_packet_follows);
    nread += read(buffer, reserved);

    return nread;
  }

  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.writeByte(SshMessageType::KexInit);
    size_t nwritten = 1;

    buffer.add(cookie, sizeof(cookie));
    nwritten += sizeof(cookie);
    nwritten += writeNameList(buffer, kex_algorithms);
    nwritten += writeNameList(buffer, server_host_key_algorithms);
    nwritten += writeNameList(buffer, encryption_algorithms_client_to_server);
    nwritten += writeNameList(buffer, encryption_algorithms_server_to_client);
    nwritten += writeNameList(buffer, mac_algorithms_client_to_server);
    nwritten += writeNameList(buffer, mac_algorithms_server_to_client);
    nwritten += writeNameList(buffer, compression_algorithms_client_to_server);
    nwritten += writeNameList(buffer, compression_algorithms_server_to_client);
    nwritten += writeNameList(buffer, languages_client_to_server);
    nwritten += writeNameList(buffer, languages_server_to_client);
    buffer.writeByte(first_kex_packet_follows);
    nwritten += 1;
    buffer.writeBEInt(reserved);
    nwritten += sizeof(reserved);

    return nwritten;
  }
};

struct KexEcdhInitMessage : SshMsg<KexEcdhInitMessage> {
  bytearray client_pub_key;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != SshMessageType::KexECDHInit) {
      throw EnvoyException("unexpected message type");
    }
    size_t nread = 1;
    nread += readString(buffer, client_pub_key);
    return nread;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.writeByte(SshMessageType::KexECDHInit);
    size_t nwritten = 1;
    nwritten += writeString(buffer, client_pub_key);
    return nwritten;
  }
};

struct KexEcdhReplyMsg : SshMsg<KexEcdhReplyMsg> {
  bytearray host_key;
  bytearray ephemeral_pub_key;
  bytearray signature;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != SshMessageType::KexECDHReply) {
      throw EnvoyException("unexpected message type");
    }
    size_t nread = 1;
    nread += readString(buffer, host_key);
    nread += readString(buffer, ephemeral_pub_key);
    nread += readString(buffer, signature);
    return nread;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.writeByte(SshMessageType::KexECDHReply);
    size_t nwritten = 1;
    nwritten += writeString(buffer, host_key);
    nwritten += writeString(buffer, ephemeral_pub_key);
    nwritten += writeString(buffer, signature);
    return nwritten;
  }
};

struct ServiceRequestMsg : SshMsg<ServiceRequestMsg> {
  std::string service_name;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != SshMessageType::ServiceRequest) {
      throw EnvoyException("unexpected message type");
    }
    size_t nread = 1;
    nread += readString(buffer, service_name);
    return nread;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.writeByte(SshMessageType::ServiceRequest);
    size_t nwritten = 1;
    nwritten += writeString(buffer, service_name);
    return nwritten;
  }
};

struct ServiceAcceptMsg : SshMsg<ServiceAcceptMsg> {
  std::string service_name;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != SshMessageType::ServiceAccept) {
      throw EnvoyException("unexpected message type");
    }
    size_t nread = 1;
    nread += readString(buffer, service_name);
    return nread;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.writeByte(SshMessageType::ServiceAccept);
    size_t nwritten = 1;
    nwritten += writeString(buffer, service_name);
    return nwritten;
  }
};

template <SshMessageType T> struct EmptyMsg : SshMsg<EmptyMsg<T>> {
  size_t decode(Envoy::Buffer::Instance& buffer, size_t) override {
    auto msgtype = buffer.drainInt<SshMessageType>();
    if (msgtype != T) {
      throw EnvoyException("unexpected message type");
    }
    return 1;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.writeByte(T);
    return 1;
  }
};

struct AnyMsg : SshMsg<AnyMsg> {
  SshMessageType msg_type;
  bytearray raw_packet; // includes msg_type

  size_t decode(Envoy::Buffer::Instance& buffer, size_t payload_size) override {
    msg_type = buffer.peekInt<SshMessageType>();
    raw_packet.resize(payload_size);
    buffer.copyOut(0, payload_size, raw_packet.data());
    buffer.drain(payload_size);
    return payload_size;
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const override {
    buffer.add(raw_packet.data(), raw_packet.size());
    return 1;
  }

  template <typename T> std::enable_if_t<std::is_base_of_v<SshMsg<T>, T>, T> unwrap() const {
    T t{};
    Envoy::Buffer::OwnedImpl buf;
    buf.add(raw_packet.data(), raw_packet.size());
    t.decode(buf, buf.length());
    buf.drain(buf.length());
    return t;
  }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec