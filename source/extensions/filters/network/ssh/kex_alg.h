#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/kex.h"
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr auto kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org";
static constexpr auto kexAlgoCurve25519SHA256 = "curve25519-sha256";

static const string_list preferredKexAlgos = {kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH};

static constexpr auto cipherAES128GCM = "aes128-gcm@openssh.com";
static constexpr auto cipherAES256GCM = "aes256-gcm@openssh.com";
static constexpr auto cipherChacha20Poly1305 = "chacha20-poly1305@openssh.com";

static const string_list preferredCiphers = {cipherChacha20Poly1305, cipherAES128GCM, cipherAES256GCM};

static const std::unordered_set<std::string> invalid_key_exchange_methods = {
  "ext-info-c",
  "ext-info-s",
  "kex-strict-c-v00@openssh.com",
  "kex-strict-s-v00@openssh.com",
};

static const string_list rsaSha2256HostKeyAlgs = {
  "rsa-sha2-256",
  "rsa-sha2-256-cert-v01@openssh.com",
};

static const string_list rsaSha2512HostKeyAlgs = {
  "rsa-sha2-512",
  "rsa-sha2-512-cert-v01@openssh.com",
};

inline string_list algorithmsForKeyFormat(std::string_view key_format) {
  if (key_format == "ssh-rsa") {
    return {"rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"};
  } else if (key_format == "ssh-rsa-cert-v01@openssh.com") {
    return {"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com"};
  }
  return {std::string(key_format)};
}

// TODO: non-AEAD cipher support
static const string_list supportedMACs{
  // "hmac-sha2-256-etm@openssh.com",
  // "hmac-sha2-512-etm@openssh.com",
  // "hmac-sha2-256",
  // "hmac-sha2-512",
  // "hmac-sha1",
  // "hmac-sha1-96",
};

// from go ssh/common.go
static const std::set<std::string> aeadCiphers = {
  cipherAES128GCM,
  cipherAES256GCM,
  cipherChacha20Poly1305,
};

struct DirectionAlgorithms {
  std::string cipher;
  std::string mac;
  std::string compression;

  auto operator<=>(const DirectionAlgorithms&) const = default;
};

struct Algorithms {
  std::string kex;
  std::string host_key;
  DirectionAlgorithms w;
  DirectionAlgorithms r;

  auto operator<=>(const Algorithms&) const = default;
};

struct HandshakeMagics {
  std::string client_version;
  std::string server_version;
  bytes client_kex_init;
  bytes server_kex_init;

  void encode(Envoy::Buffer::Instance& buffer) const {
    wire::write_opt<wire::LengthPrefixed>(buffer, client_version);
    wire::write_opt<wire::LengthPrefixed>(buffer, server_version);
    wire::write_opt<wire::LengthPrefixed>(buffer, client_kex_init);
    wire::write_opt<wire::LengthPrefixed>(buffer, server_kex_init);
  }
};

enum HashFunction {
  SHA256 = SSH_DIGEST_SHA256,
  SHA512 = SSH_DIGEST_SHA512,
};

struct KexResult {
  bytes exchange_hash; // 'H'
  bytes shared_secret; // 'K'; not encoded as a length-prefixed bignum
  bytes host_key_blob;
  bytes signature;
  HashFunction hash;
  bytes session_id;
  bytes server_ephemeral_pub_key;
  Algorithms algorithms;
  bool client_supports_ext_info;
  bool server_supports_ext_info;

  auto operator<=>(const KexResult&) const = default;

  void encodeSharedSecret(bytes& out) {
    Envoy::Buffer::OwnedImpl tmp;
    wire::writeBignum(tmp, shared_secret);
    wire::flushTo<bytes>(tmp, out);
  }
};
using KexResultSharedPtr = std::shared_ptr<KexResult>;

class KexAlgorithm : public Logger::Loggable<Logger::Id::filter> {
  friend class Kex;

public:
  KexAlgorithm(const HandshakeMagics* magics, const Algorithms* algs,
               const openssh::SSHKey* signer)
      : magics_(magics), algs_(algs), signer_(signer) {
    ASSERT(magics_ != nullptr);
    ASSERT(algs_ != nullptr);
    ASSERT(signer_ != nullptr);
  }
  virtual ~KexAlgorithm() = default;

  using MessageTypeList = absl::flat_hash_set<wire::SshMessageType>;
  virtual absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message& msg) PURE;
  virtual absl::StatusOr<std::optional<KexResultSharedPtr>> handleClientRecv(wire::Message& msg) PURE;
  virtual absl::StatusOr<wire::Message> buildClientInit() PURE;
  virtual const MessageTypeList& clientInitMessageTypes() const PURE;
  virtual absl::StatusOr<wire::Message> buildServerReply(const KexResult&) PURE;
  virtual const MessageTypeList& serverReplyMessageTypes() const PURE;

protected:
  const HandshakeMagics* magics_;
  const Algorithms* algs_;
  const openssh::SSHKey* signer_;

  bool shouldIgnorePacket() {
    if (!should_ignore_one_) {
      return false;
    }
    should_ignore_one_ = false;
    return true;
  }

  bytes computeExchangeHash(const auto& host_key_blob,
                            const auto& client_pub_key,
                            const auto& server_pub_key,
                            const auto& shared_secret) {
    Envoy::Buffer::OwnedImpl exchangeHash;
    magics_->encode(exchangeHash);
    wire::write_opt<wire::LengthPrefixed>(exchangeHash, host_key_blob);
    wire::write_opt<wire::LengthPrefixed>(exchangeHash, client_pub_key);
    wire::write_opt<wire::LengthPrefixed>(exchangeHash, server_pub_key);
    wire::writeBignum(exchangeHash, shared_secret);

    fixed_bytes<SSH_DIGEST_MAX_LENGTH> digest_buf;
    size_t digest_len = digest_buf.size();
    auto buf = exchangeHash.linearize(static_cast<uint32_t>(exchangeHash.length()));
    auto hash_alg = kex_hash_from_name(algs_->kex.c_str());
    ssh_digest_memory(hash_alg, buf, exchangeHash.length(), digest_buf.data(), digest_len);
    exchangeHash.drain(exchangeHash.length());
    digest_len = ssh_digest_bytes(hash_alg);
    return to_bytes(bytes_view{digest_buf.begin(), digest_len});
  }

  absl::StatusOr<KexResultSharedPtr> computeServerResult(const auto& host_key_blob,
                                                         const auto& client_pub_key,
                                                         const auto& server_pub_key,
                                                         const auto& shared_secret) {

    auto result = std::make_shared<KexResult>();
    result->algorithms = *algs_;
    result->host_key_blob = host_key_blob;

    auto digest = computeExchangeHash(host_key_blob, client_pub_key, server_pub_key, shared_secret);
    auto sig = signer_->sign(digest);
    if (!sig.ok()) {
      return statusf("error signing exchange hash: {}", sig.status());
    }

    result->exchange_hash = to_bytes(digest);
    result->shared_secret = to_bytes(shared_secret);
    result->signature = *sig;
    result->hash = SHA256;
    result->server_ephemeral_pub_key = to_bytes(server_pub_key);
    // session id is not set here

    return result;
  }

  absl::StatusOr<KexResultSharedPtr> computeClientResult(const auto& host_key_blob,
                                                         const auto& client_pub_key,
                                                         const auto& server_pub_key,
                                                         const auto& shared_secret,
                                                         const bytes& signature) {

    auto result = std::make_shared<KexResult>();
    result->algorithms = *algs_;
    result->host_key_blob = host_key_blob;

    auto digest = computeExchangeHash(host_key_blob, client_pub_key, server_pub_key, shared_secret);

    auto server_host_pubkey = openssh::SSHKey::fromPublicKeyBlob(host_key_blob);
    if (!server_host_pubkey.ok()) {
      return statusf("error reading host key blob: {}", server_host_pubkey.status());
    }

    auto stat = (*server_host_pubkey)->verify(signature, digest);
    if (!stat.ok()) {
      return statusf("signature failed verification: {}", stat);
    }

    result->exchange_hash = to_bytes(digest);
    result->shared_secret = to_bytes(shared_secret);
    result->signature = signature;
    result->hash = SHA256;
    result->server_ephemeral_pub_key = to_bytes(server_pub_key);
    // session id is not set here

    return result;
  }

private:
  bool should_ignore_one_{};

  void ignoreNextPacket() {
    should_ignore_one_ = true;
  }
};

struct Curve25519Keypair {
  std::array<uint8_t, 32> priv;
  std::array<uint8_t, 32> pub;
};

static const std::array<uint8_t, 32> curve25519_zeros{};

class Curve25519Sha256KexAlgorithm : public KexAlgorithm {
public:
  using KexAlgorithm::KexAlgorithm;

  absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message& msg) override;
  absl::StatusOr<std::optional<KexResultSharedPtr>> handleClientRecv(wire::Message& msg) override;
  absl::StatusOr<wire::Message> buildClientInit() override;
  const MessageTypeList& clientInitMessageTypes() const override;
  absl::StatusOr<wire::Message> buildServerReply(const KexResult&) override;
  const MessageTypeList& serverReplyMessageTypes() const override;

private:
  Curve25519Keypair client_keypair_;

  absl::Status buildResult(uint8_t client_pub_key[32], uint8_t shared_secret[32],
                           Curve25519Keypair server_keypair);
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec