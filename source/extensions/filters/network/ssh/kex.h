#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "absl/strings/str_split.h"
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/keys.h"
#include <netinet/in.h>
#include "envoy/filesystem/filesystem.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "openssl/curve25519.h"

extern "C" {
#include "openssh/ssherr.h"
#include "openssh/kex.h"
#include "openssh/sshbuf.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct HostKeyPair {
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
  std::string client_kex_init;
  std::string server_kex_init;

  void writeTo(std::function<void(const void* data, size_t len)> writer) const {
    writer(client_version.data(), client_version.size());
    writer(server_version.data(), server_version.size());
    writer(client_kex_init.data(), client_kex_init.size());
    writer(server_kex_init.data(), server_kex_init.size());
  }
};

enum hash_function {
  SHA256,
  SHA512,
};

struct kex_result_t {
  std::string H;
  std::string K;
  std::string HostKey;
  std::string Signature;
  hash_function Hash;
  std::string SessionID;
  std::string EphemeralPubKey;
};

class KexAlgorithm {
  friend class Kex;

public:
  KexAlgorithm(const handshake_magics_t* magics, const algorithms_t* algs,
               const HostKeyPair* signer)
      : magics_(magics), algs_(algs), signer_(signer) {}
  virtual ~KexAlgorithm() = default;

  virtual error_or<bool> HandleServer(Envoy::Buffer::Instance& buffer) PURE;
  virtual error_or<bool> HandleClient(Envoy::Buffer::Instance& buffer) PURE;
  virtual std::unique_ptr<kex_result_t> Result() PURE;

protected:
  const handshake_magics_t* magics_;
  const algorithms_t* algs_;
  const HostKeyPair* signer_;

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

  error_or<bool> HandleServer(Envoy::Buffer::Instance& buffer) override {
    auto [packet, err] = readPacket<KexEcdhInitMessage>(buffer);
    if (err) {
      return {false, err};
    }
    if (auto sz = packet.payload.client_pub_key.length(); sz != 32) {
      return {false, fmt::format("invalid peer public key size (expected 32, got {})", sz)};
    }
    uint8_t client_pub_key[32];
    memcpy(client_pub_key, packet.payload.client_pub_key.data(), sizeof(client_pub_key));

    curve25519_keypair_t server_keypair;
    kexc25519_keygen(server_keypair.priv, server_keypair.pub);

    uint8_t shared_secret[32];
    if (!X25519(shared_secret, server_keypair.priv, client_pub_key)) {
      return {false, "curve25519 key exchange failed"};
    }
    if (CRYPTO_memcmp(shared_secret, curve25519_zeros, 32)) {
      return {false, "peer's curve25519 public value has wrong order"};
    }

    SHA256_CTX hash;
    SHA256_Init(&hash);
    using namespace std::placeholders;
    magics_->writeTo(std::bind(&SHA256_Update, &hash, _1, _2));
    SHA256_Update(&hash, signer_->pub->ed25519_pk, 32);
    SHA256_Update(&hash, client_pub_key, 32);
    SHA256_Update(&hash, server_keypair.pub, 32);
    libssh::SshBufPtr bn(sshbuf_new());
    if (auto err = sshbuf_put_bignum2_bytes(bn.get(), shared_secret, 32); err < 0) {
      return {false, std::string(ssh_err(err))};
    }
    SHA256_Update(&hash, bn.get(), sshbuf_len(bn.get()));

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &hash);

    uint8_t* sig;
    size_t sig_len;
    if (auto err = sshkey_sign(signer_->priv.get(), &sig, &sig_len, digest, sizeof(digest),
                               algs_->host_key.c_str(), nullptr, nullptr, 0);
        err < 0) {
      return {false, std::string(ssh_err(err))};
    }
    result_ = new kex_result_t;
    result_->H.resize(sizeof(digest));
    memcpy(result_->H.data(), digest, sizeof(digest));
    result_->K.resize(sizeof(digest));
    memcpy(result_->K.data(), bn.get(), sshbuf_len(bn.get()));
    result_->HostKey.resize(32);
    memcpy(result_->HostKey.data(), signer_->pub->ed25519_pk, 32);
    result_->Signature.resize(sig_len);
    memcpy(result_->Signature.data(), sig, sig_len);
    result_->Hash = SHA256;
    result_->EphemeralPubKey.resize(sizeof(server_keypair.pub));
    memcpy(result_->EphemeralPubKey.data(), server_keypair.pub, sizeof(server_keypair.pub));
    // session id is not set here

    return {true, std::nullopt};
  }
  error_or<bool> HandleClient(Envoy::Buffer::Instance& /*buffer*/) override {
    throw std::runtime_error("unsupported");
  }

  std::unique_ptr<kex_result_t> Result() override {
    auto p = std::unique_ptr<kex_result_t>(result_);
    result_ = nullptr;
    return p;
  };

private:
  kex_result_t* result_;
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
  std::unique_ptr<kex_result_t> kex_result;

  bool kex_init_sent{};
  bool kex_init_received{};
  bool kex_negotiated_algorithms{};

  bool kexHasExtInfoInAuth() const { return (flags & KEX_HAS_EXT_INFO_IN_AUTH) != 0; }
  void setKexHasExtInfoInAuth() { flags |= KEX_HAS_EXT_INFO_IN_AUTH; }

  bool kexRSASHA2256Supported() const { return (flags & KEX_RSA_SHA2_256_SUPPORTED) != 0; }
  void setKexRSASHA2256Supported() { flags |= KEX_RSA_SHA2_256_SUPPORTED; }

  bool kexRSASHA2512Supported() const { return (flags & KEX_RSA_SHA2_512_SUPPORTED) != 0; }
  void setKexRSASHA2512Supported() { flags |= KEX_RSA_SHA2_512_SUPPORTED; }
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

class Kex {
public:
  Kex(GenericProxy::ServerCodecCallbacks* callbacks, Filesystem::Instance& fs)
      : callbacks_(callbacks), state_(std::make_unique<kex_state_t>()), fs_(fs), is_server_(true) {
    (void)callbacks_;
    (void)fs_;
  }

  void setVersionStrings(const std::string& ours, const std::string& peer) {
    if (is_server_) {
      state_->magics.server_version = ours;
      state_->magics.client_version = peer;
    } else {
      state_->magics.server_version = peer;
      state_->magics.client_version = ours;
    }
  }

  std::tuple<bool, error> doInitialKex(Envoy::Buffer::Instance& buffer) noexcept {
    if (!state_->kex_init_received) {
      auto [peerKexInit, err] = readPacket<KexInitMessage>(buffer); // no mac initially
      if (err) {
        return {false, err};
      }

      {
        Envoy::Buffer::OwnedImpl tmp;
        size_t sz = writePacket(tmp, peerKexInit); // no mac initially
        std::string raw_peer_kex_init(static_cast<char*>(tmp.linearize(sz)), sz);
        tmp.drain(sz);

        if (is_server_) {
          state_->magics.client_kex_init = std::move(raw_peer_kex_init);
        } else {
          state_->magics.server_kex_init = std::move(raw_peer_kex_init);
        }
      }

      state_->peer_kex = std::move(peerKexInit.payload);
      state_->kex_init_received = true;
    }
    if (!state_->kex_init_sent) {
      KexInitMessage* server_kex_init = &state_->our_kex;
      std::copy(preferredKexAlgos.begin(), preferredKexAlgos.end(),
                std::back_inserter(server_kex_init->kex_algorithms));
      if (is_server_) {
        server_kex_init->kex_algorithms.push_back("kex-strict-s-v00@openssh.com");
      } else {
        server_kex_init->kex_algorithms.push_back("kex-strict-c-v00@openssh.com");
      }
      server_kex_init->encryption_algorithms_client_to_server = preferredCiphers;
      server_kex_init->encryption_algorithms_server_to_client = preferredCiphers;
      server_kex_init->mac_algorithms_client_to_server = supportedMACs;
      server_kex_init->mac_algorithms_server_to_client = supportedMACs;
      server_kex_init->compression_algorithms_client_to_server = {"none"};
      server_kex_init->compression_algorithms_server_to_client = {"none"};
      RAND_bytes(server_kex_init->cookie, sizeof(server_kex_init->cookie));
      for (const auto& hostKey : host_keys_) {
        auto algs = algorithmsForKeyFormat(sshkey_ssh_name(hostKey.priv.get()));
        std::copy(algs.begin(), algs.end(),
                  std::back_inserter(server_kex_init->server_host_key_algorithms));
      }

      Envoy::Buffer::OwnedImpl writeBuf;
      encodeAsPacket(writeBuf, *server_kex_init);

      {
        std::string raw_kex_init = writeBuf.toString();
        if (is_server_) {
          state_->magics.server_kex_init = std::move(raw_kex_init);
        } else {
          state_->magics.client_kex_init = std::move(raw_kex_init);
        }
      }

      callbacks_->writeToConnection(writeBuf);
      state_->kex_init_sent = true;
    }
    if (!state_->kex_negotiated_algorithms && state_->kex_init_sent && state_->kex_init_received) {
      if (auto [algs, err] = negotiateAlgorithms(); err) {
        return {false, err};
      } else {
        state_->kex_negotiated_algorithms = true;
        state_->negotiated_algorithms = algs;
      }

      auto [algImpl, err] = newAlgorithmImpl();
      if (err) {
        return {false, err};
      }

      if (state_->peer_kex.first_kex_packet_follows) {
        if ((state_->peer_kex.kex_algorithms[0] != state_->our_kex.kex_algorithms[0]) ||
            (state_->peer_kex.server_host_key_algorithms[0] !=
             state_->our_kex.server_host_key_algorithms[0])) {
          algImpl->ignoreNextPacket();
        }
      }

      state_->alg_impl = std::move(algImpl);
      return {false, std::nullopt};
    }

    if (state_->alg_impl) {
      bool done{};
      if (is_server_) {
        auto [d, err] = state_->alg_impl->HandleServer(buffer);
        if (err) {
          return {false, err};
        }
        done = d;
      } else {
        auto [d, err] = state_->alg_impl->HandleClient(buffer);
        if (err) {
          return {false, err};
        }
        done = d;
      }
      if (done) {
        auto result = state_->alg_impl->Result();
        state_->kex_result = std::move(result);
        state_->alg_impl.reset();
      }
    }

    if (state_->kex_result) {
      auto firstKeyExchange = !state_->session_id.has_value();
      if (firstKeyExchange) {
        state_->session_id = state_->kex_result->H;
      }
      state_->kex_result->SessionID = state_->session_id.value();

      KexEcdhReplyMsg reply;
      reply.host_key = state_->kex_result->HostKey;
      reply.ephemeral_pub_key = state_->kex_result->EphemeralPubKey;
      reply.signature = state_->kex_result->Signature;
      Envoy::Buffer::OwnedImpl writeBuf;
      encodeAsPacket(writeBuf, reply);
      callbacks_->writeToConnection(writeBuf);
    }

    return {false, std::nullopt};
  }

  error_or<algorithms_t> negotiateAlgorithms() noexcept {
    if (is_server_) {
      state_->client_has_ext_info = absl::c_contains(state_->peer_kex.kex_algorithms, "ext-info-c");
      state_->kex_strict =
          absl::c_contains(state_->peer_kex.kex_algorithms, "kex-strict-c-v00@openssh.com");
    } else {
      state_->server_has_ext_info = absl::c_contains(state_->peer_kex.kex_algorithms, "ext-info-s");
      state_->kex_strict =
          absl::c_contains(state_->peer_kex.kex_algorithms, "kex-strict-s-v00@openssh.com");
    }

    if (is_server_) {
      NameList common;
      absl::c_set_union(state_->peer_kex.server_host_key_algorithms, rsaSha2256HostKeyAlgs,
                        std::back_inserter(common));
      if (!common.empty()) {
        state_->setKexRSASHA2256Supported();
      }
      common.clear();
      absl::c_set_union(state_->peer_kex.server_host_key_algorithms, rsaSha2512HostKeyAlgs,
                        std::back_inserter(common));
      if (!common.empty()) {
        state_->setKexRSASHA2512Supported();
      }
    }

    algorithms_t result{};
    {
      auto [common_kex, err] = findCommon("key exchange", state_->peer_kex.kex_algorithms,
                                          state_->our_kex.kex_algorithms);
      if (err) {
        return {{}, err};
      }
      result.kex = common_kex;
    }
    {
      auto [common_host_key, err] =
          findCommon("host key", state_->peer_kex.server_host_key_algorithms,
                     state_->our_kex.server_host_key_algorithms);
      if (err) {
        return {{}, err};
      }
      result.host_key = common_host_key;
    }

    direction_algorithms_t *stoc, *ctos;
    if (is_server_) {
      stoc = &result.w;
      ctos = &result.r;
    } else {
      stoc = &result.r;
      ctos = &result.w;
    }

    {
      auto [common_cipher, err] = findCommon(
          "client to server cipher", state_->peer_kex.encryption_algorithms_client_to_server,
          state_->our_kex.encryption_algorithms_client_to_server);
      if (err) {
        return {{}, err};
      }
      ctos->cipher = common_cipher;
    }
    {
      auto [common_cipher, err] = findCommon(
          "server to client cipher", state_->peer_kex.encryption_algorithms_server_to_client,
          state_->our_kex.encryption_algorithms_server_to_client);
      if (err) {
        return {{}, err};
      }
      stoc->cipher = common_cipher;
    }

    if (!aeadCiphers.contains(ctos->cipher)) {
      auto [common_mac, err] =
          findCommon("client to server MAC", state_->peer_kex.mac_algorithms_client_to_server,
                     state_->our_kex.mac_algorithms_client_to_server);
      if (err) {
        return {{}, err};
      }
      ctos->mac = common_mac;
    }

    if (!aeadCiphers.contains(stoc->cipher)) {
      auto [common_mac, err] =
          findCommon("server to client MAC", state_->peer_kex.mac_algorithms_server_to_client,
                     state_->our_kex.mac_algorithms_server_to_client);
      if (err) {
        return {{}, err};
      }
      stoc->mac = common_mac;
    }

    {
      auto [common_compression, err] = findCommon(
          "client to server compression", state_->peer_kex.compression_algorithms_client_to_server,
          state_->our_kex.compression_algorithms_client_to_server);
      if (err) {
        return {{}, err};
      }
      ctos->compression = common_compression;
    }
    {
      auto [common_compression, err] = findCommon(
          "server to client compression", state_->peer_kex.compression_algorithms_server_to_client,
          state_->our_kex.compression_algorithms_server_to_client);
      if (err) {
        return {{}, err};
      }
      stoc->compression = common_compression;
    }

    return {result, std::nullopt};
  }

  error_or<std::unique_ptr<KexAlgorithm>> newAlgorithmImpl() {
    if (state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256 ||
        state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256LibSSH) {
      auto hostKey = pickHostKey(state_->negotiated_algorithms.host_key);
      if (!hostKey) {
        return {nullptr, fmt::format("no matching host key for algorithm: {}",
                                     state_->negotiated_algorithms.host_key)};
      }
      return {std::make_unique<Curve25519Sha256KexAlgorithm>(
                  &state_->magics, &state_->negotiated_algorithms, hostKey),
              std::nullopt};
    }
    return {nullptr, fmt::format("unsupported key exchange algorithm: {}",
                                 state_->negotiated_algorithms.kex)};
  }

  const HostKeyPair* pickHostKey(const std::string& alg) {
    for (const auto& keypair : host_keys_) {
      for (const auto& keyAlg : algorithmsForKeyFormat(sshkey_ssh_name(keypair.pub.get()))) {
        if (alg == keyAlg) {
          return &keypair;
        }
      }
    }
    return nullptr;
  }

  // from go ssh/common.go findCommon()
  error_or<std::string> findCommon(std::string_view what, const NameList& client,
                                   const NameList& server) {
    for (const auto& c : client) {
      for (const auto& s : server) {
        if (c == s) {
          return {c, std::nullopt};
        }
      }
    }
    return {"", fmt::format("no common algorithm for {}; client offered: {}; server offered: {}",
                            what, client, server)};
  }

  void loadHostKeys() {
    // static constexpr auto rsaPriv =
    //     "source/extensions/filters/network/ssh/testdata/test_host_rsa_key";
    // static constexpr auto rsaPub =
    //     "source/extensions/filters/network/ssh/testdata/test_host_rsa_key.pub";
    // static constexpr auto rsaPriv = "/etc/ssh/ssh_host_rsa_key";
    // static constexpr auto rsaPub = "/etc/ssh/ssh_host_rsa_key.pub";
    // loadSshKeyPair(rsaPriv, rsaPub);

    // static constexpr auto ed25519Priv = "/etc/ssh/ssh_host_ed25519_key";
    // static constexpr auto ed25519Pub = "/etc/ssh/ssh_host_ed25519_key.pub";
    static constexpr auto ed25519Priv =
        "source/extensions/filters/network/ssh/testdata/test_host_ed25519_key";
    static constexpr auto ed25519Pub =
        "source/extensions/filters/network/ssh/testdata/test_host_ed25519_key.pub";
    loadSshKeyPair(ed25519Priv, ed25519Pub);
  }

  void loadSshKeyPair(const char* privKeyPath, const char* pubKeyPath) {
    if (fs_.fileExists(privKeyPath) && fs_.fileExists(pubKeyPath)) {
      auto priv = loadSshPrivateKey(privKeyPath);
      auto pub = loadSshPublicKey(pubKeyPath);
      host_keys_.emplace_back(HostKeyPair{
          .priv = std::move(priv),
          .pub = std::move(pub),
      });
    }
  }

private:
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  std::unique_ptr<kex_state_t> state_;
  Filesystem::Instance& fs_;
  bool is_server_;
  std::vector<HostKeyPair> host_keys_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec