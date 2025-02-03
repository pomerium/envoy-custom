#include "source/extensions/filters/network/ssh/kex.h"
#include "messages.h"
#include "source/common/buffer/buffer_impl.h"
#include "openssl/curve25519.h"
#include "source/extensions/filters/network/ssh/keys.h"
#include "absl/strings/str_split.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

extern "C" {
#include "openssh/ssherr.h"
#include "openssh/kex.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

error_or<bool> Curve25519Sha256KexAlgorithm::HandleServer(Envoy::Buffer::Instance& buffer) {
  auto [peerMsg, err] = readPacket<KexEcdhInitMessage>(buffer);
  if (err) {
    return {false, err};
  }
  if (auto sz = peerMsg.client_pub_key.size(); sz != 32) {
    return {false, fmt::format("invalid peer public key size (expected 32, got {})", sz)};
  }
  uint8_t client_pub_key[32];
  memcpy(client_pub_key, peerMsg.client_pub_key.data(), sizeof(client_pub_key));

  curve25519_keypair_t server_keypair;
  kexc25519_keygen(server_keypair.priv, server_keypair.pub);

  uint8_t shared_secret[32];
  if (!X25519(shared_secret, server_keypair.priv, client_pub_key)) {
    return {false, "curve25519 key exchange failed"};
  }
  if (!CRYPTO_memcmp(shared_secret, curve25519_zeros, 32)) {
    return {false, "peer's curve25519 public value has wrong order"};
  }

  result_.reset(new kex_result_t);
  result_->Algorithms = *algs_;

  {
    bytearray hostKeyType;
    copyWithLengthPrefix(hostKeyType, algs_->host_key);
    bytearray hostKeyData;
    copyWithLengthPrefix(hostKeyData, signer_->pub->ed25519_pk, static_cast<size_t>(32));
    std::copy(hostKeyData.begin(), hostKeyData.end(), std::back_inserter(hostKeyType));
    result_->HostKeyBlob = hostKeyType;
  }

  Envoy::Buffer::OwnedImpl exchangeHash;

  magics_->writeTo([&exchangeHash](const void* p, size_t sz) { exchangeHash.add(p, sz); });
  exchangeHash.writeBEInt<uint32_t>(result_->HostKeyBlob.size());
  exchangeHash.add(result_->HostKeyBlob.data(), result_->HostKeyBlob.size());
  exchangeHash.writeBEInt<uint32_t>(sizeof(client_pub_key));
  exchangeHash.add(client_pub_key, sizeof(client_pub_key));
  exchangeHash.writeBEInt<uint32_t>(sizeof(server_keypair.pub));
  exchangeHash.add(server_keypair.pub, sizeof(server_keypair.pub));
  writeBignum(exchangeHash, shared_secret, sizeof(shared_secret));

  uint8_t digest[SSH_DIGEST_MAX_LENGTH];
  size_t digest_len = sizeof(digest);
  auto buf = exchangeHash.linearize(exchangeHash.length());
  auto hash_alg = kex_hash_from_name(algs_->kex.c_str());
  ssh_digest_memory(hash_alg, buf, exchangeHash.length(), digest, digest_len);
  digest_len = ssh_digest_bytes(hash_alg);
  sshbuf_dump_data(buf, exchangeHash.length(), stderr);
  exchangeHash.drain(exchangeHash.length());

  uint8_t* sig;
  size_t sig_len;
  if (auto err = sshkey_sign(signer_->priv.get(), &sig, &sig_len, digest,
                             digest_len, // <- NB: not sizeof(digest)
                             algs_->host_key.c_str(), nullptr, nullptr, 0);
      err < 0) {
    return {false, std::string(ssh_err(err))};
  }
  result_->H.resize(digest_len);
  memcpy(result_->H.data(), digest, digest_len);
  result_->K.resize(sizeof(shared_secret));
  memcpy(result_->K.data(), shared_secret, sizeof(shared_secret));

  result_->Signature.resize(sig_len);
  memcpy(result_->Signature.data(), sig, sig_len);
  result_->Hash = SHA256;
  result_->EphemeralPubKey.resize(sizeof(server_keypair.pub));
  memcpy(result_->EphemeralPubKey.data(), server_keypair.pub, sizeof(server_keypair.pub));
  // session id is not set here

  return {true, std::nullopt};
}

error_or<bool> Curve25519Sha256KexAlgorithm::HandleClient(Envoy::Buffer::Instance& /*buffer*/) {
  throw std::runtime_error("unsupported");
}

std::shared_ptr<kex_result_t>&& Curve25519Sha256KexAlgorithm::Result() {
  return std::move(result_);
};

Kex::Kex(GenericProxy::ServerCodecCallbacks* callbacks, KexCallbacks& kexCallbacks,
         Filesystem::Instance& fs)
    : callbacks_(callbacks), kex_callbacks_(kexCallbacks), state_(std::make_unique<kex_state_t>()),
      fs_(fs), is_server_(true) {}

void Kex::setVersionStrings(const std::string& ours, const std::string& peer) {
  if (is_server_) {
    state_->magics.server_version = ours;
    state_->magics.client_version = peer;
  } else {
    state_->magics.server_version = peer;
    state_->magics.client_version = ours;
  }
}

std::tuple<bool, error> Kex::doInitialKex(Envoy::Buffer::Instance& buffer) noexcept {
  if (!state_->kex_init_received) {
    auto [peerKexInit, err] = readPacket<KexInitMessage>(buffer); // no mac initially
    if (err) {
      return {false, err};
    }

    {
      Envoy::Buffer::OwnedImpl tmp;
      auto sz = peerKexInit.encode(tmp);
      auto tmpBytes = static_cast<uint8_t*>(tmp.linearize(sz));
      bytearray raw_peer_kex_init(tmpBytes, tmpBytes + sz);
      tmp.drain(sz);

      if (is_server_) {
        state_->magics.client_kex_init = std::move(raw_peer_kex_init);
      } else {
        state_->magics.server_kex_init = std::move(raw_peer_kex_init);
      }
    }

    state_->peer_kex = std::move(peerKexInit);
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

    {
      Envoy::Buffer::OwnedImpl tmp;
      auto sz = server_kex_init->encode(tmp);
      auto tmpBytes = static_cast<uint8_t*>(tmp.linearize(sz));
      bytearray raw_kex_init(tmpBytes, tmpBytes + sz);
      if (is_server_) {
        state_->magics.server_kex_init = std::move(raw_kex_init);
      } else {
        state_->magics.client_kex_init = std::move(raw_kex_init);
      }
    }

    Envoy::Buffer::OwnedImpl writeBuf;
    writePacket(writeBuf, *server_kex_init);
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
      state_->kex_result = state_->alg_impl->Result();
      state_->alg_impl.reset();
    }
  }

  if (!state_->kex_result) {
    return {false, std::nullopt};
  }

  if (!state_->kex_reply_sent) {
    auto firstKeyExchange = !state_->session_id.has_value();
    if (firstKeyExchange) {
      state_->session_id = state_->kex_result->H;
    }
    state_->kex_result->SessionID = state_->session_id.value();

    KexEcdhReplyMsg reply;
    reply.host_key = state_->kex_result->HostKeyBlob;
    reply.ephemeral_pub_key = state_->kex_result->EphemeralPubKey;
    reply.signature = state_->kex_result->Signature;
    Envoy::Buffer::OwnedImpl writeBuf;
    writePacket(writeBuf, reply);
    callbacks_->writeToConnection(writeBuf);
    state_->kex_reply_sent = true;
    // don't return yet, sent newkeys first
  }

  if (!state_->kex_newkeys_sent) {
    Envoy::Buffer::OwnedImpl buf;
    writePacket(buf, EmptyMsg<SshMessageType::NewKeys>{});
    callbacks_->writeToConnection(buf);
    state_->kex_newkeys_sent = true;
    // return here to yield and wait for client newkeys. if the buffer isn't empty this will
    // be called again immediately.
    return {false, std::nullopt};
  }

  if (!state_->kex_newkeys_received) {
    auto [_, err] = readPacket<EmptyMsg<SshMessageType::NewKeys>>(buffer);
    if (err.has_value()) {
      return {false, err};
    }
    state_->kex_newkeys_received = true;
  }

  if (state_->kex_newkeys_received) {
    kex_callbacks_.setKexResult(state_->kex_result);
    return {true, std::nullopt};
  }
  return {false, std::nullopt};
}

error_or<algorithms_t> Kex::negotiateAlgorithms() noexcept {
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

  // logic below is translated from go ssh/common.go findAgreedAlgorithms
  algorithms_t result{};
  {
    auto [common_kex, err] =
        findCommon("key exchange", state_->peer_kex.kex_algorithms, state_->our_kex.kex_algorithms);
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
    auto [common_cipher, err] = findCommon("client to server cipher",
                                           state_->peer_kex.encryption_algorithms_client_to_server,
                                           state_->our_kex.encryption_algorithms_client_to_server);
    if (err) {
      return {{}, err};
    }
    ctos->cipher = common_cipher;
  }
  {
    auto [common_cipher, err] = findCommon("server to client cipher",
                                           state_->peer_kex.encryption_algorithms_server_to_client,
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

error_or<std::string> Kex::findCommon(std::string_view what, const NameList& client,
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

error_or<std::unique_ptr<KexAlgorithm>> Kex::newAlgorithmImpl() {
  if (state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256 ||
      state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256LibSSH) {
    auto hostKey = pickHostKey(state_->negotiated_algorithms.host_key);
    if (!hostKey) {
      return {nullptr, fmt::format("no matching host key for algorithm: {}",
                                   state_->negotiated_algorithms.host_key)};
    }
    return {std::make_unique<Curve25519Sha256KexAlgorithm>(&state_->magics,
                                                           &state_->negotiated_algorithms, hostKey),
            std::nullopt};
  }
  return {nullptr,
          fmt::format("unsupported key exchange algorithm: {}", state_->negotiated_algorithms.kex)};
}

const host_keypair_t* Kex::pickHostKey(const std::string& alg) {
  for (const auto& keypair : host_keys_) {
    for (const auto& keyAlg : algorithmsForKeyFormat(sshkey_ssh_name(keypair.pub.get()))) {
      if (alg == keyAlg) {
        return &keypair;
      }
    }
  }
  return nullptr;
}

void Kex::loadHostKeys() {
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

void Kex::loadSshKeyPair(const char* privKeyPath, const char* pubKeyPath) {
  if (fs_.fileExists(privKeyPath) && fs_.fileExists(pubKeyPath)) {
    try {
      auto priv = loadSshPrivateKey(privKeyPath);
      auto pub = loadSshPublicKey(pubKeyPath);
      host_keys_.emplace_back(host_keypair_t{
          .priv = std::move(priv),
          .pub = std::move(pub),
      });
    } catch (const EnvoyException& e) {
      ENVOY_LOG(error, e.what());
      return;
    }
  }
}

bool kex_state_t::kexHasExtInfoInAuth() const { return (flags & KEX_HAS_EXT_INFO_IN_AUTH) != 0; }

void kex_state_t::setKexHasExtInfoInAuth() { flags |= KEX_HAS_EXT_INFO_IN_AUTH; }

bool kex_state_t::kexRSASHA2256Supported() const {
  return (flags & KEX_RSA_SHA2_256_SUPPORTED) != 0;
}

void kex_state_t::setKexRSASHA2256Supported() { flags |= KEX_RSA_SHA2_256_SUPPORTED; }

bool kex_state_t::kexRSASHA2512Supported() const {
  return (flags & KEX_RSA_SHA2_512_SUPPORTED) != 0;
}

void kex_state_t::setKexRSASHA2512Supported() { flags |= KEX_RSA_SHA2_512_SUPPORTED; }

void handshake_magics_t::writeTo(std::function<void(const void* data, size_t len)> writer) const {
  std::string buf;
  copyWithLengthPrefix(buf, client_version);
  writer(buf.data(), buf.size());
  copyWithLengthPrefix(buf, server_version);
  writer(buf.data(), buf.size());
  copyWithLengthPrefix(buf, client_kex_init);
  writer(buf.data(), buf.size());
  copyWithLengthPrefix(buf, server_kex_init);
  writer(buf.data(), buf.size());
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec