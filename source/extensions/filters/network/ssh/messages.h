#pragma once

#include <cstdint>
#include <type_traits>
#include <string>
#include "source/common/buffer/buffer_impl.h"
#include "openssl/rand.h"
#include "source/extensions/filters/network/ssh/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum class SshMessageType : uint8_t {
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

inline size_t readVariableBytes(Envoy::Buffer::Instance& buffer, std::string& out, size_t len) {
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

inline size_t readString(Envoy::Buffer::Instance& buffer, std::string& out) {
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

inline size_t writeString(Envoy::Buffer::Instance& buffer, const std::string& str) {
  size_t nwritten = 0;
  buffer.writeBEInt(str.size());
  nwritten += sizeof(str.size());
  buffer.add(str);
  nwritten += str.size();
  return nwritten;
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
  if (list.empty()) {
    return 0;
  }
  uint32_t size = 0;
  for (const auto& entry : list) {
    size += entry.length();
  }
  size += list.size() - 1; // commas
  buffer.writeBEInt(size);

  for (size_t i = 0; i < list.size(); i++) {
    buffer.add(list[i]);
    if (i < list.size() - 1) {
      buffer.writeByte(',');
    }
  }
  return sizeof(size) + size;
}

template <typename T> struct SshPacket {
  uint32_t packet_length;
  uint8_t padding_length;
  T payload;
  std::string padding;
  // uint8_t mac[20];
};

template <typename T, bool = std::is_trivially_move_assignable_v<T>> struct SshMessage {
  virtual ~SshMessage() = default;
  virtual size_t decode(Envoy::Buffer::Instance&) PURE;
  virtual size_t encode(Envoy::Buffer::Instance&) const PURE;
};

template <typename T>
std::enable_if_t<std::is_base_of_v<SshMessage<T>, T>, std::tuple<SshPacket<T>, error>>
readPacket(Envoy::Buffer::Instance& buffer) noexcept {
  try {
    SshPacket<T> packet{};
    auto bufferSize = buffer.length();
    size_t nread = 0;
    nread += read(buffer, packet.packet_length);
    nread += read(buffer, packet.padding_length);
    {
      auto n = packet.payload.decode(buffer);
      nread += n;
      if (n != (packet.packet_length - packet.padding_length - 1)) {
        return {{},
                fmt::format("unexpected packet payload size of {} bytes (expected {})", nread,
                            packet.packet_length - packet.padding_length - 1)};
      }
    }
    nread += readVariableBytes(buffer, packet.padding, packet.padding_length);
    // if (require_mac) {
    //   nread += readFixedBytes<sizeof(packet.mac)>(buffer, packet.mac);
    // }
    if (nread != bufferSize) {
      return {{}, fmt::format("bad packet length: {} (expected {})", bufferSize, nread)};
    }
    return {packet, std::nullopt};
  } catch (const EnvoyException& e) {
    return {{}, fmt::format("error decoding packet: {}", e.what())};
  }
}

template <typename T>
std::enable_if_t<std::is_base_of_v<SshMessage<T>, T>, size_t>
writePacket(Envoy::Buffer::Instance& out, const SshPacket<T>& packet) {
  size_t nwritten = 0;
  out.writeBEInt(packet.packet_length);
  nwritten += sizeof(packet.packet_length);
  out.writeByte(packet.padding_length);
  nwritten += sizeof(packet.padding_length);
  nwritten += packet.payload.encode(out);
  out.add(packet.padding);
  nwritten += packet.padding_length;
  return nwritten;
}

template <typename T>
std::enable_if_t<std::is_base_of_v<SshMessage<T>, T>, void>
encodeAsPacket(Envoy::Buffer::Instance& out, T& payload) {
  Envoy::Buffer::OwnedImpl payloadBytes;
  size_t payload_length = payload.encode(payloadBytes);

  // RFC4253 § 6
  constexpr auto cipher_block_size = 8; // TODO
  uint8_t padding_length = cipher_block_size - (1 + payload_length) % cipher_block_size;
  if (padding_length < 4) {
    padding_length += cipher_block_size;
  }
  // std::max<uint8_t>(4, cipher_block_size - (1 + payload_length) % cipher_block_size);
  uint32_t packet_length = sizeof(padding_length) + payload_length + padding_length;

  out.writeBEInt(packet_length);
  out.writeByte(padding_length);
  out.move(payloadBytes);

  auto paddingSlice = out.reserveSingleSlice(padding_length);
  RAND_bytes(static_cast<uint8_t*>(paddingSlice.slice().mem_), paddingSlice.slice().len_);
  paddingSlice.commit(padding_length);
}

struct KexInitMessage : SshMessage<KexInitMessage> {
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

  size_t decode(Envoy::Buffer::Instance& buffer) override {
    auto msgtype = buffer.drainInt<uint8_t>();
    if (msgtype != static_cast<uint8_t>(SshMessageType::KexInit)) {
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

struct KexEcdhInitMessage : SshMessage<KexEcdhInitMessage> {
  std::string client_pub_key;

  size_t decode(Envoy::Buffer::Instance& buffer) override {
    auto msgtype = buffer.drainInt<uint8_t>();
    if (msgtype != static_cast<uint8_t>(SshMessageType::KexECDHInit)) {
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

struct KexEcdhReplyMsg : SshMessage<KexEcdhReplyMsg> {
  std::string host_key;
  std::string ephemeral_pub_key;
  std::string signature;

  size_t decode(Envoy::Buffer::Instance& buffer) override {
    auto msgtype = buffer.drainInt<uint8_t>();
    if (msgtype != static_cast<uint8_t>(SshMessageType::KexECDHReply)) {
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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec