#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include <netinet/in.h>
#include "envoy/filesystem/filesystem.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

extern "C" {
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct host_keypair_t {
  libssh::SshKeyPtr priv;
  libssh::SshKeyPtr pub;
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
  bytearray client_kex_init;
  bytearray server_kex_init;

  void writeTo(std::function<void(const void* data, size_t len)> writer) const;
};

enum hash_function {
  SHA256 = SSH_DIGEST_SHA256,
  SHA512 = SSH_DIGEST_SHA512,
};

struct kex_result_t {
  bytearray H; // exchange hash
  bytearray K; // raw shared secret, not encoded as a length-prefixed bignum
  bytearray HostKeyBlob;
  bytearray Signature;
  hash_function Hash;
  bytearray SessionID;
  bytearray EphemeralPubKey;
  algorithms_t Algorithms;

  void EncodeSharedSecret(bytearray& out) {
    Envoy::Buffer::OwnedImpl tmp;
    writeBignum(tmp, K.data(), K.size());
    out.resize(tmp.length());
    out.shrink_to_fit();
    tmp.copyOut(0, out.size(), out.data());
  }
};

class KexAlgorithm : public Logger::Loggable<Logger::Id::filter> {
  friend class Kex;

public:
  KexAlgorithm(const handshake_magics_t* magics, const algorithms_t* algs,
               const host_keypair_t* signer)
      : magics_(magics), algs_(algs), signer_(signer) {}
  virtual ~KexAlgorithm() = default;

  virtual absl::Status HandleServerRecv(const AnyMsg& msg) PURE;
  virtual absl::StatusOr<AnyMsg> HandleClientSend() PURE;
  virtual absl::Status HandleClientRecv(const AnyMsg& msg) PURE;
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

  void ignoreNextPacket() { should_ignore_one_ = true; }
};

struct curve25519_keypair_t {
  uint8_t priv[32];
  uint8_t pub[32];
};

static const uint8_t curve25519_zeros[32]{};

class Curve25519Sha256KexAlgorithm : public KexAlgorithm {
public:
  using KexAlgorithm::KexAlgorithm;

  absl::Status HandleServerRecv(const AnyMsg& msg) override;
  absl::StatusOr<AnyMsg> HandleClientSend() override;
  absl::Status HandleClientRecv(const AnyMsg& msg) override;

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
  std::optional<bytearray> session_id{};
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

static const NameList rsaSha2256HostKeyAlgs = {
    "rsa-sha2-256",
    "rsa-sha2-256-cert-v01@openssh.com",
};

static const NameList rsaSha2512HostKeyAlgs = {
    "rsa-sha2-512",
    "rsa-sha2-512-cert-v01@openssh.com",
};

inline NameList algorithmsForKeyFormat(const std::string& keyFormat) {
  if (keyFormat == "ssh-rsa") {
    return {"rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"};
  } else if (keyFormat == "ssh-rsa-cert-v01@openssh.com") {
    return {"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com"};
  }
  return {keyFormat};
}

class KexCallbacks {
public:
  virtual ~KexCallbacks() = default;
  virtual void setKexResult(std::shared_ptr<kex_result_t> kex_result) PURE;
};

class Kex : public VersionExchangeCallbacks,
            public MessageHandler,
            public Logger::Loggable<Logger::Id::filter> {
public:
  Kex(TransportCallbacks& transportCallbacks, KexCallbacks& kexCallbacks, Filesystem::Instance& fs,
      bool isServer);

  absl::Status doInitialKex(Envoy::Buffer::Instance& buffer) noexcept;
  absl::StatusOr<algorithms_t> negotiateAlgorithms() noexcept;
  absl::StatusOr<std::unique_ptr<KexAlgorithm>> newAlgorithmImpl();
  const host_keypair_t* pickHostKey(const std::string& alg);
  const host_keypair_t* getHostKey(const std::string& pkalg);
  absl::StatusOr<std::string> findCommon(std::string_view what, const NameList& client,
                                         const NameList& server);
  void loadHostKeys();
  void loadSshKeyPair(const char* privKeyPath, const char* pubKeyPath);

  // HandshakeCallbacks
  void setVersionStrings(const std::string& ours, const std::string& peer) override;

private:
  absl::Status handleMessage(AnyMsg&& msg) noexcept override;
  absl::Status sendKexInit() noexcept;

  TransportCallbacks& transport_;
  KexCallbacks& kex_callbacks_;
  std::unique_ptr<kex_state_t> state_;
  Filesystem::Instance& fs_;
  bool is_server_;
  std::vector<host_keypair_t> host_keys_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec