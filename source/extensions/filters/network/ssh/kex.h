#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>

#include "envoy/filesystem/filesystem.h"

#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/kex.h"
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct host_keypair_t {
  openssh::SSHKey priv;
  openssh::SSHKey pub;
};

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
};

struct Algorithms {
  std::string kex;
  std::string host_key;
  DirectionAlgorithms w;
  DirectionAlgorithms r;
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
  bytes ephemeral_pub_key;
  Algorithms algorithms;

  void encodeSharedSecret(bytes& out) {
    Envoy::Buffer::OwnedImpl tmp;
    wire::writeBignum(tmp, shared_secret);
    wire::flushTo<bytes>(tmp, out);
  }
};

class KexAlgorithm : public Logger::Loggable<Logger::Id::filter> {
  friend class Kex;

public:
  KexAlgorithm(const HandshakeMagics* magics, const Algorithms* algs,
               const host_keypair_t* signer)
      : magics_(magics), algs_(algs), signer_(signer) {}
  virtual ~KexAlgorithm() = default;

  virtual absl::Status handleServerRecv(wire::Message& msg) PURE;
  virtual absl::StatusOr<wire::Message> handleClientSend() PURE;
  virtual absl::Status handleClientRecv(wire::Message& msg) PURE;
  virtual std::shared_ptr<KexResult>&& result() PURE;

protected:
  const HandshakeMagics* magics_;
  const Algorithms* algs_;
  const host_keypair_t* signer_;

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

  absl::StatusOr<std::shared_ptr<KexResult>> computeServerResult(const auto& host_key_blob,
                                                                 const auto& client_pub_key,
                                                                 const auto& server_pub_key,
                                                                 const auto& shared_secret) {

    auto result = std::make_shared<KexResult>();
    result->algorithms = *algs_;
    result->host_key_blob = host_key_blob;

    auto digest = computeExchangeHash(host_key_blob, client_pub_key, server_pub_key, shared_secret);
    auto sig = signer_->priv.sign(digest);
    if (!sig.ok()) {
      return sig.status();
    }

    result->exchange_hash = to_bytes(digest);
    result->shared_secret = to_bytes(shared_secret);
    result->signature = *sig;
    result->hash = SHA256;
    result->ephemeral_pub_key = to_bytes(server_pub_key);
    // session id is not set here

    return result;
  }

  absl::StatusOr<std::shared_ptr<KexResult>> computeClientResult(const auto& host_key_blob,
                                                                 const auto& client_pub_key,
                                                                 const auto& server_pub_key,
                                                                 const auto& shared_secret,
                                                                 const bytes& signature) {

    auto result = std::make_shared<KexResult>();
    result->algorithms = *algs_;
    result->host_key_blob = host_key_blob;

    auto digest = computeExchangeHash(host_key_blob, client_pub_key, server_pub_key, shared_secret);

    auto server_host_key = openssh::SSHKey::fromBlob(host_key_blob);
    if (!server_host_key.ok()) {
      return server_host_key.status();
    }

    auto stat = server_host_key->verify(signature, digest);
    if (!stat.ok()) {
      return stat;
    }

    result->exchange_hash = to_bytes(digest);
    result->shared_secret = to_bytes(shared_secret);
    result->signature = signature;
    result->hash = SHA256;
    result->ephemeral_pub_key = to_bytes(server_pub_key);
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

  absl::Status handleServerRecv(wire::Message& msg) override;
  absl::StatusOr<wire::Message> handleClientSend() override;
  absl::Status handleClientRecv(wire::Message& msg) override;

  std::shared_ptr<KexResult>&& result() override;

private:
  std::shared_ptr<KexResult> result_;
  Curve25519Keypair client_keypair_;

  absl::Status buildResult(uint8_t client_pub_key[32], uint8_t shared_secret[32],
                           Curve25519Keypair server_keypair);
};

struct KexState {
  bool is_server{};
  bool client_has_ext_info{};
  bool server_has_ext_info{};
  bool kex_strict{};
  bool ext_info_received{};
  wire::KexInitMessage our_kex{};
  wire::KexInitMessage peer_kex{};
  Algorithms negotiated_algorithms{};
  HandshakeMagics magics{};
  std::optional<bytes> session_id;
  uint32_t flags{};

  std::unique_ptr<KexAlgorithm> alg_impl;
  std::shared_ptr<KexResult> kex_result;

  bool kex_init_sent{};
  bool kex_init_received{};
  bool kex_negotiated_algorithms{};
  bool kex_reply_sent{};
  bool kex_newkeys_sent{};
  bool kex_newkeys_received{};

  bool kexHasExtInfoInAuth() const;
  void setKexHasExtInfoInAuth();

  bool kexRSASHA2256Supported() const;
  void setKexRSASHA2256Supported();

  bool kexRSASHA2512Supported() const;
  void setKexRSASHA2512Supported();
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

class KexCallbacks {
public:
  virtual ~KexCallbacks() = default;
  virtual void setKexResult(std::shared_ptr<KexResult> kex_result) PURE;
};

enum class KexMode {
  None = 0,
  Server = 1,
  Client = 2,
};

class Kex : public VersionExchangeCallbacks,
            public SshMessageHandler,
            public Logger::Loggable<Logger::Id::filter> {
public:
  Kex(TransportCallbacks& transport_callbacks,
      KexCallbacks& kex_callbacks,
      Filesystem::Instance& fs,
      KexMode mode);

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  absl::Status doInitialKex(Envoy::Buffer::Instance& buffer) noexcept;
  absl::StatusOr<Algorithms> negotiateAlgorithms() noexcept;
  absl::StatusOr<std::unique_ptr<KexAlgorithm>> newAlgorithmImpl();
  const host_keypair_t* pickHostKey(std::string_view alg);
  const host_keypair_t* getHostKey(const std::string& pkalg);
  absl::StatusOr<std::string> findCommon(std::string_view what, const string_list& client,
                                         const string_list& server);
  absl::Status loadHostKeys();
  absl::Status loadSshKeyPair(const std::string& priv_key_path, const std::string& pub_key_path);
  void setVersionStrings(const std::string& ours, const std::string& peer) override;

private:
  absl::Status handleMessage(wire::Message&& msg) noexcept override;
  absl::Status sendKexInit() noexcept;

  TransportCallbacks& transport_;
  KexCallbacks& kex_callbacks_;
  std::unique_ptr<KexState> state_;
  Filesystem::Instance& fs_;
  bool is_server_;
  std::vector<host_keypair_t> host_keys_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec