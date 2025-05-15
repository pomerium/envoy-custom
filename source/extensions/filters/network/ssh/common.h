#pragma once

#include <string>
#include <unordered_set>
#include <unordered_map>

#include "fmt/std.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage end

#include "source/common/types.h" // IWYU pragma: keep

// envoy internal stream id
using stream_id_t = uint64_t;

// packet sequence number
using seqnum_t = uint32_t;

using namespace std::literals;

static constexpr auto CipherAES128GCM = "aes128-gcm@openssh.com";
static constexpr auto CipherAES256GCM = "aes256-gcm@openssh.com";
static constexpr auto CipherChacha20Poly1305 = "chacha20-poly1305@openssh.com";
static constexpr auto CipherAES128CTR = "aes128-ctr";
static constexpr auto CipherAES192CTR = "aes192-ctr";
static constexpr auto CipherAES256CTR = "aes256-ctr";

static const std::unordered_set<std::string> InvalidKeyExchangeMethods = {
  "ext-info-c",
  "ext-info-s",
  "kex-strict-c-v00@openssh.com",
  "kex-strict-s-v00@openssh.com",
};

static const string_list RsaSha2256HostKeyAlgs = {
  "rsa-sha2-256",
  "rsa-sha2-256-cert-v01@openssh.com",
};

static const string_list RsaSha2512HostKeyAlgs = {
  "rsa-sha2-512",
  "rsa-sha2-512-cert-v01@openssh.com",
};

static const string_list SupportedMACs{
  "hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512-etm@openssh.com",
  "umac-128-etm@openssh.com",
};

const std::unordered_map<std::string_view, size_t> MACKeySizes = {
  {"hmac-sha2-512-etm@openssh.com", 64},
  {"hmac-sha2-256-etm@openssh.com", 32},
  {"umac-128-etm@openssh.com", 16},
};

// from go ssh/common.go
static const std::unordered_set<std::string> AEADCiphers = {
  CipherAES128GCM,
  CipherAES256GCM,
  CipherChacha20Poly1305,
};

struct DirectionAlgorithms {
  std::string cipher;
  std::string mac;
  std::string compression;

  auto operator<=>(const DirectionAlgorithms&) const = default;
};

struct DirectionTags {
  char iv_tag;
  char key_tag;
  char mac_key_tag;

  auto operator<=>(const DirectionTags&) const = default;
};

struct Algorithms {
  std::string kex;
  std::string host_key;
  DirectionAlgorithms client_to_server;
  DirectionAlgorithms server_to_client;

  auto operator<=>(const Algorithms&) const = default;
};
