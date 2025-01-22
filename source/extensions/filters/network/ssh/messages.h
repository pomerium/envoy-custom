#pragma once

#include <cstdint>
#include <type_traits>
#include <vector>
#include <string>
#include "source/common/buffer/buffer_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using error = std::optional<std::string>;
using NameList = std::vector<std::string>;

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

template <size_t N>
inline size_t readFixedBytes(Envoy::Buffer::Instance& buffer, std::array<uint8_t, N>& out) {
  if (buffer.length() < N) {
    throw EnvoyException("short read");
  }
  buffer.copyOut(0, N, out.data());
  buffer.drain(N);
  return N;
}

inline size_t readNameList(Envoy::Buffer::Instance& buffer, NameList& out) {
  size_t nread = 0;
  auto size = buffer.drainBEInt<uint32_t>();
  nread += sizeof(size);
  // read up to 'size' bytes
  if (buffer.length() < size) {
    // invalid
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

template <typename T> struct SshPacket {
  uint32_t size;
  uint8_t padding_size;
  T msg;
  std::string padding;
  std::array<uint8_t, 20> mac;
};

struct SshMessage {
  virtual ~SshMessage() = default;
  virtual size_t decode(Envoy::Buffer::Instance&) PURE;
};

template <typename T>
std::enable_if_t<std::is_base_of_v<SshMessage, T>, std::tuple<SshPacket<T>, error>>
decodePacket(Envoy::Buffer::Instance& buffer, bool require_mac = true) noexcept {
  try {
    SshPacket<T> packet{};
    size_t nread = 0;
    nread += read(buffer, packet.size);
    nread += read(buffer, packet.padding_size);
    {
      T msg{};
      auto n = msg.decode(buffer);
      nread += n;
      if (n != (packet.size - packet.padding_size - 1)) {
        return {{},
                fmt::format("unexpected packet payload size of {} bytes (expected {})", nread,
                            packet.size - packet.padding_size - 1)};
      }
    }
    nread += readVariableBytes(buffer, packet.padding, packet.padding_size);
    if (require_mac) {
      nread += readFixedBytes(buffer, packet.mac);
    }
    return {packet, std::nullopt};
  } catch (const EnvoyException& e) {
    return {{}, fmt::format("error decoding packet: {}", e.what())};
  }
}

struct KexInitMessage : SshMessage {
  std::array<uint8_t, 16> cookie;
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
  bool first_kex_packet_follows;
  uint32_t reserved;

  size_t decode(Envoy::Buffer::Instance& buffer) override {
    auto msgtype = buffer.drainInt<uint8_t>();
    if (msgtype != static_cast<uint8_t>(SshMessageType::KexInit)) {
      throw EnvoyException("unexpected message type");
    }
    size_t nread = 1;

    nread += readFixedBytes(buffer, cookie);
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
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec