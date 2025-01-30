#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include <netinet/in.h>
#include "envoy/filesystem/filesystem.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

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

struct direction_t {
  std::basic_string<uint8_t> iv_tag;
  std::basic_string<uint8_t> key_tag;
  std::basic_string<uint8_t> mac_key_tag;
};

struct cipher_mode_t {
  int32_t keySize;

  std::function<std::unique_ptr<PacketCipher>(std::basic_string_view<uint8_t>)> create;
};

static const direction_t clientKeys{{'A'}, {'C'}, {'E'}};
static const direction_t serverKeys{{'B'}, {'D'}, {'F'}};

static const std::map<std::string, cipher_mode_t> cipherModes{
    {cipherChacha20Poly1305, {64, [](std::basic_string_view<uint8_t> key) {
                                return std::make_unique<Chacha20Poly1305Cipher>(key);
                              }}}};

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
  std::string client_kex_init;
  std::string server_kex_init;

  void writeTo(std::function<void(const void* data, size_t len)> writer) const;
};

enum hash_function {
  SHA256,
  SHA512,
};

struct kex_result_t {
  std::string H;
  std::string K;
  std::string HostKeyBlob;
  std::string Signature;
  hash_function Hash;
  std::string SessionID;
  std::string EphemeralPubKey;
  algorithms_t Algorithms;
};

class KexAlgorithm : public Logger::Loggable<Logger::Id::filter> {
  friend class Kex;

public:
  KexAlgorithm(const handshake_magics_t* magics, const algorithms_t* algs,
               const host_keypair_t* signer)
      : magics_(magics), algs_(algs), signer_(signer) {}
  virtual ~KexAlgorithm() = default;

  virtual error_or<bool> HandleServer(Envoy::Buffer::Instance& buffer) PURE;
  virtual error_or<bool> HandleClient(Envoy::Buffer::Instance& buffer) PURE;
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

  error_or<bool> HandleServer(Envoy::Buffer::Instance& buffer) override;
  error_or<bool> HandleClient(Envoy::Buffer::Instance& buffer) override;

  std::shared_ptr<kex_result_t>&& Result() override;

private:
  std::shared_ptr<kex_result_t> result_;
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
  std::optional<std::string> session_id{};
  uint32_t flags{};

  std::unique_ptr<KexAlgorithm> alg_impl;
  std::shared_ptr<kex_result_t> kex_result;

  bool kex_init_sent{};
  bool kex_init_received{};
  bool kex_negotiated_algorithms{};

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

class Kex : public Logger::Loggable<Logger::Id::filter> {
public:
  Kex(GenericProxy::ServerCodecCallbacks* callbacks, KexCallbacks& kexCallbacks,
      Filesystem::Instance& fs);

  void setVersionStrings(const std::string& ours, const std::string& peer);
  std::tuple<bool, error> doInitialKex(Envoy::Buffer::Instance& buffer) noexcept;
  error_or<algorithms_t> negotiateAlgorithms() noexcept;
  error_or<std::unique_ptr<KexAlgorithm>> newAlgorithmImpl();
  const host_keypair_t* pickHostKey(const std::string& alg);
  error_or<std::string> findCommon(std::string_view what, const NameList& client,
                                   const NameList& server);

  void loadHostKeys();

  void loadSshKeyPair(const char* privKeyPath, const char* pubKeyPath);

private:
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  KexCallbacks& kex_callbacks_;
  std::unique_ptr<kex_state_t> state_;
  Filesystem::Instance& fs_;
  bool is_server_;
  std::vector<host_keypair_t> host_keys_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec