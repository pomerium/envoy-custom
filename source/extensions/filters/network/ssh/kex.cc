#include "source/extensions/filters/network/ssh/kex.h"

#include "openssl/curve25519.h"

#include "source/common/buffer/buffer_impl.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include <algorithm>

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/kex.h"
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::Status Curve25519Sha256KexAlgorithm::HandleServerRecv(const wire::SshMsg& msg) {
  const auto& peerMsg = dynamic_cast<const wire::KexEcdhInitMessage&>(msg);

  if (auto sz = peerMsg.client_pub_key->size(); sz != 32) {
    return absl::AbortedError(
        fmt::format("invalid peer public key size (expected 32, got {})", sz));
  }
  fixed_bytes<32> client_pub_key;
  std::copy_n(peerMsg.client_pub_key->begin(), 32, client_pub_key.begin());

  curve25519_keypair_t server_keypair;
  kexc25519_keygen(server_keypair.priv.data(), server_keypair.pub.data());

  fixed_bytes<32> shared_secret;
  if (!X25519(shared_secret.data(), server_keypair.priv.data(), client_pub_key.data())) {
    return absl::AbortedError("curve25519 key exchange failed");
  }
  if (!CRYPTO_memcmp(shared_secret.data(), curve25519_zeros.data(), 32)) {
    return absl::AbortedError("peer's curve25519 public value has wrong order");
  }

  result_.reset(new kex_result_t);
  result_->Algorithms = *algs_;
  auto blob = signer_->pub.toBlob();
  if (!blob.ok()) {
    return blob.status();
  }
  result_->HostKeyBlob = *blob;

  Envoy::Buffer::OwnedImpl exchangeHash;
  magics_->encode(exchangeHash);
  wire::write_opt<wire::LengthPrefixed>(exchangeHash, result_->HostKeyBlob);
  wire::write_opt<wire::LengthPrefixed>(exchangeHash, client_pub_key);
  wire::write_opt<wire::LengthPrefixed>(exchangeHash, server_keypair.pub);
  wire::writeBignum(exchangeHash, shared_secret);

  fixed_bytes<SSH_DIGEST_MAX_LENGTH> digest_buf;
  size_t digest_len = sizeof(digest_buf);
  auto buf = exchangeHash.linearize(exchangeHash.length());
  auto hash_alg = kex_hash_from_name(algs_->kex.c_str());
  ssh_digest_memory(hash_alg, buf, exchangeHash.length(), digest_buf.data(), digest_len);
  exchangeHash.drain(exchangeHash.length());
  digest_len = ssh_digest_bytes(hash_alg);
  auto digest = bytes_view<>{digest_buf.begin(), digest_len};

  auto sig = signer_->priv.sign(digest);
  if (!sig.ok()) {
    return sig.status();
  }

  result_->H = to_bytes(digest);
  result_->K = to_bytes(shared_secret);

  result_->Signature = *sig;
  result_->Hash = SHA256;
  result_->EphemeralPubKey = to_bytes(server_keypair.pub);
  // session id is not set here

  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<wire::SshMsg>> Curve25519Sha256KexAlgorithm::HandleClientSend() {
  curve25519_keypair_t client_keypair;
  kexc25519_keygen(client_keypair.priv.data(), client_keypair.pub.data());
  client_keypair_ = client_keypair;
  auto msg = std::make_unique<wire::KexEcdhInitMessage>();

  msg->client_pub_key = bytes{client_keypair.pub.begin(), client_keypair.pub.end()};
  return msg;
}

absl::Status Curve25519Sha256KexAlgorithm::HandleClientRecv(const wire::SshMsg& msg) {
  auto& serverMsg = dynamic_cast<const wire::KexEcdhReplyMsg&>(msg);

  if (auto sz = serverMsg.ephemeral_pub_key->size(); sz != 32) {
    return absl::AbortedError(
        fmt::format("invalid peer public key size (expected 32, got {})", sz));
  }

  fixed_bytes<32> server_pub_key;
  std::copy_n(serverMsg.ephemeral_pub_key->begin(), 32, server_pub_key.begin());

  fixed_bytes<32> shared_secret;
  if (!X25519(shared_secret.data(), client_keypair_.priv.data(), server_pub_key.data())) {
    return absl::AbortedError("curve25519 key exchange failed");
  }
  if (!CRYPTO_memcmp(shared_secret.data(), curve25519_zeros.data(), 32)) {
    return absl::AbortedError("peer's curve25519 public value has wrong order");
  }

  result_.reset(new kex_result_t);
  result_->Algorithms = *algs_;
  result_->HostKeyBlob = *serverMsg.host_key;

  Envoy::Buffer::OwnedImpl exchangeHash;
  magics_->encode(exchangeHash);
  wire::write_opt<wire::LengthPrefixed>(exchangeHash, result_->HostKeyBlob);
  wire::write_opt<wire::LengthPrefixed>(exchangeHash, client_keypair_.pub);
  wire::write_opt<wire::LengthPrefixed>(exchangeHash, server_pub_key);
  wire::writeBignum(exchangeHash, shared_secret);

  fixed_bytes<SSH_DIGEST_MAX_LENGTH> digest_buf;
  size_t digest_len = digest_buf.size();
  auto buf = exchangeHash.linearize(exchangeHash.length());
  auto hash_alg = kex_hash_from_name(algs_->kex.c_str());
  ssh_digest_memory(hash_alg, buf, exchangeHash.length(), digest_buf.data(), digest_len);
  exchangeHash.drain(exchangeHash.length());
  digest_len = ssh_digest_bytes(hash_alg);
  auto digest = bytes_view<>{digest_buf.begin(), digest_len};

  auto server_host_key = openssh::SSHKey::fromBlob(serverMsg.host_key);
  if (!server_host_key.ok()) {
    return server_host_key.status();
  }

  auto stat = server_host_key->verify(*serverMsg.signature, digest);
  if (!stat.ok()) {
    return stat;
  }

  result_->H = to_bytes(digest);
  result_->K = to_bytes(shared_secret);
  result_->Signature = *serverMsg.signature;
  result_->Hash = SHA256;
  result_->EphemeralPubKey = *serverMsg.ephemeral_pub_key;
  // session id is not set here

  return absl::OkStatus();
}

std::shared_ptr<kex_result_t>&& Curve25519Sha256KexAlgorithm::Result() {
  return std::move(result_);
};

Kex::Kex(TransportCallbacks& transportCallbacks, KexCallbacks& kexCallbacks,
         Filesystem::Instance& fs, bool isServer)
    : transport_(transportCallbacks), kex_callbacks_(kexCallbacks),
      state_(std::make_unique<kex_state_t>()), fs_(fs), is_server_(isServer) {
  THROW_IF_NOT_OK(loadHostKeys());
}

void Kex::setVersionStrings(const std::string& ours, const std::string& peer) {
  if (is_server_) {
    state_->magics.server_version = ours;
    state_->magics.client_version = peer;
  } else {
    state_->magics.server_version = peer;
    state_->magics.client_version = ours;
  }
}

absl::Status Kex::handleMessage(wire::SshMsg&& msg) noexcept {
  switch (msg.msg_type()) {
  case wire::SshMessageType::KexInit: {
    if (state_->kex_init_received) {
      return absl::FailedPreconditionError("unexpected KexInit message");
    }
    auto& peerKexInit = dynamic_cast<wire::KexInitMessage&>(msg);

    auto raw_peer_kex_init = encodeToBytes(peerKexInit);

    if (is_server_) {
      state_->magics.client_kex_init = std::move(raw_peer_kex_init);
    } else {
      state_->magics.server_kex_init = std::move(raw_peer_kex_init);
    }

    state_->peer_kex = std::move(peerKexInit);
    state_->kex_init_received = true;

    if (!state_->kex_init_sent) {
      if (auto err = sendKexInit(); !err.ok()) {
        return err;
      }
      state_->kex_init_sent = true;
    }
    if (!state_->kex_negotiated_algorithms && state_->kex_init_sent && state_->kex_init_received) {
      if (auto algs = negotiateAlgorithms(); !algs.ok()) {
        return algs.status();
      } else {
        state_->kex_negotiated_algorithms = true;
        state_->negotiated_algorithms = *algs;
      }

      auto algImpl = newAlgorithmImpl();
      if (!algImpl.ok()) {
        return algImpl.status();
      }

      if (state_->peer_kex.first_kex_packet_follows) {
        if ((state_->peer_kex.kex_algorithms[0] != state_->our_kex.kex_algorithms[0]) ||
            (state_->peer_kex.server_host_key_algorithms[0] !=
             state_->our_kex.server_host_key_algorithms[0])) {
          (*algImpl)->ignoreNextPacket();
        }
      }

      state_->alg_impl = std::move(*algImpl);

      if (!is_server_) {
        auto stat = state_->alg_impl->HandleClientSend();
        if (!stat.ok()) {
          return stat.status();
        }
        state_->kex_reply_sent = true;
        return transport_.sendMessageToConnection(**stat).status();
      }
      return absl::OkStatus();
    }
    break;
  }
  case wire::SshMessageType::NewKeys: {
    if (state_->kex_newkeys_received) {
      return absl::FailedPreconditionError("unexpected NewKeys message received");
    }
    state_->kex_newkeys_received = true;
    // done
    kex_callbacks_.setKexResult(state_->kex_result);
    break;
  }
  default:
    if (state_->kex_result) {
      return absl::FailedPreconditionError("unexpected message received");
    }
    if (!state_->alg_impl) {
      return absl::FailedPreconditionError("unexpected message received");
    }

    if (is_server_) {
      auto stat = state_->alg_impl->HandleServerRecv(msg);
      if (!stat.ok()) {
        return stat;
      }
    } else {
      auto stat = state_->alg_impl->HandleClientRecv(msg);
      if (!stat.ok()) {
        return stat;
      }
    }

    state_->kex_result = state_->alg_impl->Result();
    state_->alg_impl.reset();

    if (is_server_) {
      if (!state_->kex_reply_sent) {
        auto firstKeyExchange = !state_->session_id.has_value();
        if (firstKeyExchange) {
          state_->session_id = state_->kex_result->H;
        }
        state_->kex_result->SessionID = state_->session_id.value();

        wire::KexEcdhReplyMsg reply;
        reply.host_key = state_->kex_result->HostKeyBlob;
        reply.ephemeral_pub_key = state_->kex_result->EphemeralPubKey;
        reply.signature = state_->kex_result->Signature;
        if (auto err = transport_.sendMessageToConnection(reply); !err.ok()) {
          return err.status();
        }
        state_->kex_reply_sent = true;
        // don't return yet, send newkeys first
      }

      if (!state_->kex_newkeys_sent) {
        auto newkeys = wire::EmptyMsg<wire::SshMessageType::NewKeys>{};
        if (auto err = transport_.sendMessageToConnection(newkeys); !err.ok()) {
          return err.status();
        }
        state_->kex_newkeys_sent = true;
        // return here to yield and wait for client newkeys. if the buffer isn't empty this will
        // be called again immediately.
        return absl::OkStatus();
      }
    } else {
      auto firstKeyExchange = !state_->session_id.has_value();
      if (firstKeyExchange) {
        state_->session_id = state_->kex_result->H;
      }
      state_->kex_result->SessionID = state_->session_id.value();

      auto newkeys = wire::EmptyMsg<wire::SshMessageType::NewKeys>{};
      if (auto err = transport_.sendMessageToConnection(newkeys); !err.ok()) {
        return err.status();
      }
      state_->kex_newkeys_sent = true;
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<algorithms_t> Kex::negotiateAlgorithms() noexcept {
  if (is_server_) {
    state_->client_has_ext_info = absl::c_contains(*state_->peer_kex.kex_algorithms, "ext-info-c");
    state_->kex_strict =
        absl::c_contains(*state_->peer_kex.kex_algorithms, "kex-strict-c-v00@openssh.com");
  } else {
    state_->server_has_ext_info = absl::c_contains(*state_->peer_kex.kex_algorithms, "ext-info-s");
    state_->kex_strict =
        absl::c_contains(*state_->peer_kex.kex_algorithms, "kex-strict-s-v00@openssh.com");
  }

  if (is_server_) {
    string_list common;
    absl::c_set_union(*state_->peer_kex.server_host_key_algorithms, rsaSha2256HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      state_->setKexRSASHA2256Supported();
    }
    common.clear();
    absl::c_set_union(*state_->peer_kex.server_host_key_algorithms, rsaSha2512HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      state_->setKexRSASHA2512Supported();
    }
  }

  // logic below is translated from go ssh/common.go findAgreedAlgorithms
  algorithms_t result{};
  {
    auto common_kex =
        findCommon("key exchange", state_->peer_kex.kex_algorithms, state_->our_kex.kex_algorithms);
    if (!common_kex.ok()) {
      return common_kex.status();
    }
    result.kex = *common_kex;
  }
  {
    auto common_host_key = findCommon("host key", state_->peer_kex.server_host_key_algorithms,
                                      state_->our_kex.server_host_key_algorithms);
    if (!common_host_key.ok()) {
      return common_host_key.status();
    }
    result.host_key = *common_host_key;
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
    auto common_cipher = findCommon("client to server cipher",
                                    state_->peer_kex.encryption_algorithms_client_to_server,
                                    state_->our_kex.encryption_algorithms_client_to_server);
    if (!common_cipher.ok()) {
      return common_cipher.status();
    }
    ctos->cipher = *common_cipher;
  }
  {
    auto common_cipher = findCommon("server to client cipher",
                                    state_->peer_kex.encryption_algorithms_server_to_client,
                                    state_->our_kex.encryption_algorithms_server_to_client);
    if (!common_cipher.ok()) {
      return common_cipher.status();
    }
    stoc->cipher = *common_cipher;
  }

  if (!aeadCiphers.contains(ctos->cipher)) {
    auto common_mac =
        findCommon("client to server MAC", state_->peer_kex.mac_algorithms_client_to_server,
                   state_->our_kex.mac_algorithms_client_to_server);
    if (!common_mac.ok()) {
      return common_mac.status();
    }
    ctos->mac = *common_mac;
  }

  if (!aeadCiphers.contains(stoc->cipher)) {
    auto common_mac =
        findCommon("server to client MAC", state_->peer_kex.mac_algorithms_server_to_client,
                   state_->our_kex.mac_algorithms_server_to_client);
    if (!common_mac.ok()) {
      return common_mac.status();
    }
    stoc->mac = *common_mac;
  }

  {
    auto common_compression = findCommon("client to server compression",
                                         state_->peer_kex.compression_algorithms_client_to_server,
                                         state_->our_kex.compression_algorithms_client_to_server);
    if (!common_compression.ok()) {
      return common_compression.status();
    }
    ctos->compression = *common_compression;
  }
  {
    auto common_compression = findCommon("server to client compression",
                                         state_->peer_kex.compression_algorithms_server_to_client,
                                         state_->our_kex.compression_algorithms_server_to_client);
    if (!common_compression.ok()) {
      return common_compression.status();
    }
    stoc->compression = *common_compression;
  }

  return result;
}

absl::StatusOr<std::string> Kex::findCommon(std::string_view what, const string_list& client,
                                            const string_list& server) {
  for (const auto& c : client) {
    for (const auto& s : server) {
      if (c == s) {
        return c;
      }
    }
  }
  return absl::AbortedError(fmt::format(
      "no common algorithm for {}; client offered: {}; server offered: {}", what, client, server));
}

absl::StatusOr<std::unique_ptr<KexAlgorithm>> Kex::newAlgorithmImpl() {
  if (state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256 ||
      state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256LibSSH) {
    auto hostKey = pickHostKey(state_->negotiated_algorithms.host_key);
    if (!hostKey) {
      return absl::AbortedError(fmt::format("no matching host key for algorithm: {}",
                                            state_->negotiated_algorithms.host_key));
    }
    return std::make_unique<Curve25519Sha256KexAlgorithm>(&state_->magics,
                                                          &state_->negotiated_algorithms, hostKey);
  }
  return absl::UnimplementedError(
      fmt::format("unsupported key exchange algorithm: {}", state_->negotiated_algorithms.kex));
}

const host_keypair_t* Kex::pickHostKey(std::string_view alg) {
  for (const auto& keypair : host_keys_) {
    for (const auto& keyAlg : algorithmsForKeyFormat(keypair.pub.name())) {
      if (alg == keyAlg) {
        return &keypair;
      }
    }
  }
  return nullptr;
}
const host_keypair_t* Kex::getHostKey(std::string_view alg) {
  auto pktype = sshkey_type_from_name(alg.data());

  for (const auto& keypair : host_keys_) {
    if (keypair.pub.keyType() == pktype) {
      return &keypair;
    }
  }
  return nullptr;
}

absl::Status Kex::loadHostKeys() {
  auto hostKeys = transport_.codecConfig().host_keys();
  for (const auto& hostKey : hostKeys) {
    auto err = loadSshKeyPair(hostKey.private_key_file(), hostKey.public_key_file());
    if (!err.ok()) {
      return err;
    }
  }
  return absl::OkStatus();
}

absl::Status Kex::loadSshKeyPair(std::string_view privKeyPath, std::string_view pubKeyPath) {
  auto priv = openssh::SSHKey::fromPrivateKeyFile(privKeyPath);
  if (!priv.ok()) {
    return priv.status();
  }
  auto pub = openssh::SSHKey::fromPublicKeyFile(pubKeyPath);
  if (!pub.ok()) {
    return pub.status();
  }
  host_keys_.emplace_back(host_keypair_t{
      .priv = std::move(*priv),
      .pub = std::move(*pub),
  });
  return absl::OkStatus();
}

bool kex_state_t::kexHasExtInfoInAuth() const {
  return (flags & KEX_HAS_EXT_INFO_IN_AUTH) != 0;
}

void kex_state_t::setKexHasExtInfoInAuth() {
  flags |= KEX_HAS_EXT_INFO_IN_AUTH;
}

bool kex_state_t::kexRSASHA2256Supported() const {
  return (flags & KEX_RSA_SHA2_256_SUPPORTED) != 0;
}

void kex_state_t::setKexRSASHA2256Supported() {
  flags |= KEX_RSA_SHA2_256_SUPPORTED;
}

bool kex_state_t::kexRSASHA2512Supported() const {
  return (flags & KEX_RSA_SHA2_512_SUPPORTED) != 0;
}

void kex_state_t::setKexRSASHA2512Supported() {
  flags |= KEX_RSA_SHA2_512_SUPPORTED;
}

absl::Status Kex::sendKexInit() noexcept {
  wire::KexInitMessage* server_kex_init = &state_->our_kex;
  std::copy(preferredKexAlgos.begin(), preferredKexAlgos.end(),
            std::back_inserter(*server_kex_init->kex_algorithms));
  if (is_server_) {
    server_kex_init->kex_algorithms->push_back("kex-strict-s-v00@openssh.com");
  } else {
    server_kex_init->kex_algorithms->push_back("kex-strict-c-v00@openssh.com");
  }
  server_kex_init->encryption_algorithms_client_to_server = preferredCiphers;
  server_kex_init->encryption_algorithms_server_to_client = preferredCiphers;
  server_kex_init->mac_algorithms_client_to_server = supportedMACs;
  server_kex_init->mac_algorithms_server_to_client = supportedMACs;
  server_kex_init->compression_algorithms_client_to_server = {"none"s};
  server_kex_init->compression_algorithms_server_to_client = {"none"s};
  RAND_bytes(server_kex_init->cookie->data(), sizeof(server_kex_init->cookie));
  for (const auto& hostKey : host_keys_) {
    auto algs = algorithmsForKeyFormat(hostKey.priv.name());
    std::copy(algs.begin(), algs.end(),
              std::back_inserter(*server_kex_init->server_host_key_algorithms));
  }

  auto raw_kex_init = encodeToBytes(*server_kex_init);
  if (is_server_) {
    state_->magics.server_kex_init = std::move(raw_kex_init);
  } else {
    state_->magics.client_kex_init = std::move(raw_kex_init);
  }

  if (auto err = transport_.sendMessageToConnection(*server_kex_init); !err.ok()) {
    return err.status();
  }
  return absl::OkStatus();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec