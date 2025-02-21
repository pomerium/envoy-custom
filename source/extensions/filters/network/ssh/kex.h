#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <netinet/in.h>

#include "envoy/filesystem/filesystem.h"

#include "source/extensions/filters/network/ssh/buffer.h"
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct host_keypair_t {
  openssh::SSHKey priv;
  openssh::SSHKey pub;
};

// from go ssh/common.go
static const std::set<std::string> aeadCiphers = {
    cipherAES128GCM,
    cipherAES256GCM,
    cipherChacha20Poly1305,
};

struct direction_algorithms_t {
  std::string cipher;
  std::string mac;
  std::string compression;
};

struct algorithms_t {
  std::string kex;
  std::string host_key;
  direction_algorithms_t w;
  direction_algorithms_t r;
};

struct handshake_magics_t {
  std::string client_version;
  std::string server_version;
  bytes client_kex_init;
  bytes server_kex_init;

  void encode(Envoy::Buffer::Instance& buffer) const {
    write_opt<LengthPrefixed>(buffer, client_version);
    write_opt<LengthPrefixed>(buffer, server_version);
    write_opt<LengthPrefixed>(buffer, client_kex_init);
    write_opt<LengthPrefixed>(buffer, server_kex_init);
  }
};

enum hash_function {
  SHA256 = SSH_DIGEST_SHA256,
  SHA512 = SSH_DIGEST_SHA512,
};

struct kex_result_t {
  bytes H; // exchange hash
  bytes K; // raw shared secret, not encoded as a length-prefixed bignum
  bytes HostKeyBlob;
  bytes Signature;
  hash_function Hash;
  bytes SessionID;
  bytes EphemeralPubKey;
  algorithms_t Algorithms;

  void EncodeSharedSecret(bytes& out) {
    Envoy::Buffer::OwnedImpl tmp;
    writeBignum(tmp, K);
    flushToBytes(tmp, out);
  }
};

class KexAlgorithm : public Logger::Loggable<Logger::Id::filter> {
  friend class Kex;

public:
  KexAlgorithm(const handshake_magics_t* magics, const algorithms_t* algs,
               const host_keypair_t* signer)
      : magics_(magics), algs_(algs), signer_(signer) {}
  virtual ~KexAlgorithm() = default;

  virtual absl::Status HandleServerRecv(const SshMsg& msg) PURE;
  virtual absl::StatusOr<std::unique_ptr<SshMsg>> HandleClientSend() PURE;
  virtual absl::Status HandleClientRecv(const SshMsg& msg) PURE;
  virtual std::shared_ptr<kex_result_t>&& Result() PURE;

protected:
  const handshake_magics_t* magics_;
  const algorithms_t* algs_;
  const host_keypair_t* signer_;

  bool shouldIgnorePacket() {
    if (!should_ignore_one_) {
      return false;
    }
    should_ignore_one_ = false;
    return true;
  }

private:
  bool should_ignore_one_{};

  void ignoreNextPacket() {
    should_ignore_one_ = true;
  }
};

struct curve25519_keypair_t {
  std::array<uint8_t, 32> priv;
  std::array<uint8_t, 32> pub;
};

static const std::array<uint8_t, 32> curve25519_zeros{};

class Curve25519Sha256KexAlgorithm : public KexAlgorithm {
public:
  using KexAlgorithm::KexAlgorithm;

  absl::Status HandleServerRecv(const SshMsg& msg) override;
  absl::StatusOr<std::unique_ptr<SshMsg>> HandleClientSend() override;
  absl::Status HandleClientRecv(const SshMsg& msg) override;

  std::shared_ptr<kex_result_t>&& Result() override;

private:
  std::shared_ptr<kex_result_t> result_;
  curve25519_keypair_t client_keypair_;

  absl::Status buildResult(uint8_t client_pub_key[32], uint8_t shared_secret[32],
                           curve25519_keypair_t server_keypair);
};

struct kex_state_t {
  bool is_server{};
  bool client_has_ext_info{};
  bool server_has_ext_info{};
  bool kex_strict{};
  bool ext_info_received{};
  KexInitMessage our_kex{};
  KexInitMessage peer_kex{};
  algorithms_t negotiated_algorithms{};
  handshake_magics_t magics{};
  std::optional<bytes> session_id{};
  uint32_t flags{};

  std::unique_ptr<KexAlgorithm> alg_impl;
  std::shared_ptr<kex_result_t> kex_result;

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

inline string_list algorithmsForKeyFormat(std::string_view keyFormat) {
  if (keyFormat == "ssh-rsa") {
    return {"rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"};
  } else if (keyFormat == "ssh-rsa-cert-v01@openssh.com") {
    return {"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com"};
  }
  return {std::string(keyFormat)};
}

class KexCallbacks {
public:
  virtual ~KexCallbacks() = default;
  virtual void setKexResult(std::shared_ptr<kex_result_t> kex_result) PURE;
};

class Kex : public VersionExchangeCallbacks,
            public SshMessageHandler,
            public Logger::Loggable<Logger::Id::filter> {
public:
  Kex(TransportCallbacks& transportCallbacks, KexCallbacks& kexCallbacks, Filesystem::Instance& fs,
      bool isServer);

  absl::Status doInitialKex(Envoy::Buffer::Instance& buffer) noexcept;
  absl::StatusOr<algorithms_t> negotiateAlgorithms() noexcept;
  absl::StatusOr<std::unique_ptr<KexAlgorithm>> newAlgorithmImpl();
  const host_keypair_t* pickHostKey(std::string_view alg);
  const host_keypair_t* getHostKey(std::string_view pkalg);
  absl::StatusOr<std::string> findCommon(std::string_view what, const string_list& client,
                                         const string_list& server);
  absl::Status loadHostKeys();
  absl::Status loadSshKeyPair(std::string_view privKeyPath, std::string_view pubKeyPath);
  void registerMessageHandlers(MessageDispatcher<SshMsg>& dispatcher) const override {
    dispatcher.registerHandler(SshMessageType::KexInit, this);
    dispatcher.registerHandler(SshMessageType::KexECDHInit, this);
    dispatcher.registerHandler(SshMessageType::KexECDHReply, this);
    dispatcher.registerHandler(SshMessageType::NewKeys, this);
  }
  // HandshakeCallbacks
  void setVersionStrings(const std::string& ours, const std::string& peer) override;

private:
  absl::Status handleMessage(SshMsg&& msg) noexcept override;
  absl::Status sendKexInit() noexcept;

  TransportCallbacks& transport_;
  KexCallbacks& kex_callbacks_;
  std::unique_ptr<kex_state_t> state_;
  Filesystem::Instance& fs_;
  bool is_server_;
  std::vector<host_keypair_t> host_keys_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec