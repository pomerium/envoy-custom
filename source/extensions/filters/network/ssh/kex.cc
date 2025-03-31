#include "source/extensions/filters/network/ssh/kex.h"

#include <algorithm>
#include <memory>

#include "openssl/curve25519.h"
#include "openssl/rand.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/kex.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::Status Curve25519Sha256KexAlgorithm::handleServerRecv(wire::Message& msg) {
  return msg.visit(
    [&](Envoy::OptRef<wire::KexEcdhInitMessage> msg) {
      if (auto sz = msg->client_pub_key->size(); sz != 32) {
        return absl::AbortedError(
          fmt::format("invalid peer public key size (expected 32, got {})", sz));
      }
      fixed_bytes<32> client_pub_key;
      std::copy_n(msg->client_pub_key->begin(), 32, client_pub_key.begin());

      Curve25519Keypair server_keypair;
      kexc25519_keygen(server_keypair.priv.data(), server_keypair.pub.data());

      fixed_bytes<32> shared_secret;
      if (!X25519(shared_secret.data(), server_keypair.priv.data(), client_pub_key.data())) {
        return absl::AbortedError("curve25519 key exchange failed");
      }
      if (!CRYPTO_memcmp(shared_secret.data(), curve25519_zeros.data(), 32)) {
        return absl::AbortedError("peer's curve25519 public value has wrong order");
      }

      auto blob = signer_->pub.toBlob();
      if (!blob.ok()) {
        return blob.status();
      }
      auto res = computeServerResult(*blob, client_pub_key, server_keypair.pub, shared_secret);
      if (!res.ok()) {
        return res.status();
      }
      result_ = *res;
      return absl::OkStatus();
    },
    [&msg](auto&) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received during key exchange: {}", msg.msg_type()));
    });
}

absl::StatusOr<wire::Message> Curve25519Sha256KexAlgorithm::handleClientSend() {
  Curve25519Keypair client_keypair;
  kexc25519_keygen(client_keypair.priv.data(), client_keypair.pub.data());
  client_keypair_ = client_keypair;
  auto msg = wire::KexEcdhInitMessage{};

  msg.client_pub_key = bytes{client_keypair.pub.begin(), client_keypair.pub.end()};
  return msg;
}

absl::Status Curve25519Sha256KexAlgorithm::handleClientRecv(wire::Message& msg) {
  return msg.visit(
    [&](Envoy::OptRef<wire::KexEcdhReplyMsg> msg) {
      if (!msg.has_value()) {
        return absl::InvalidArgumentError("unexpected KexEcdhReplyMsg received");
      }
      if (auto sz = msg->ephemeral_pub_key->size(); sz != 32) {
        return absl::AbortedError(
          fmt::format("invalid peer public key size (expected 32, got {})", sz));
      }

      fixed_bytes<32> server_pub_key;
      std::copy_n(msg->ephemeral_pub_key->begin(), 32, server_pub_key.begin());

      fixed_bytes<32> shared_secret;
      if (!X25519(shared_secret.data(), client_keypair_.priv.data(), server_pub_key.data())) {
        return absl::AbortedError("curve25519 key exchange failed");
      }
      if (!CRYPTO_memcmp(shared_secret.data(), curve25519_zeros.data(), 32)) {
        return absl::AbortedError("peer's curve25519 public value has wrong order");
      }

      auto res = computeClientResult(*msg->host_key, client_keypair_.pub, server_pub_key, shared_secret, *msg->signature);
      if (!res.ok()) {
        return res.status();
      }
      result_ = *res;
      return absl::OkStatus();
    },
    [&msg](auto&) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received during key exchange: {}", msg.msg_type()));
    });
}

std::shared_ptr<KexResult>&& Curve25519Sha256KexAlgorithm::result() {
  return std::move(result_);
};

Kex::Kex(TransportCallbacks& transport_callbacks, KexCallbacks& kex_callbacks,
         Filesystem::Instance& fs, KexMode mode)
    : transport_(transport_callbacks), kex_callbacks_(kex_callbacks),
      state_(std::make_unique<KexState>()),
      fs_(fs),
      is_server_(mode == KexMode::Server) {
  THROW_IF_NOT_OK(loadHostKeys());
}

void Kex::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::KexInit, this);
  dispatcher.registerHandler(wire::SshMessageType::KexECDHInit, this);
  dispatcher.registerHandler(wire::SshMessageType::KexECDHReply, this);
  dispatcher.registerHandler(wire::SshMessageType::NewKeys, this);
  msg_dispatcher_ = dispatcher;
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

absl::StatusOr<bool> Kex::interceptMessage(wire::Message& msg) {
  return msg.visit(
    [&](wire::ExtInfoMsg& msg) {
      transport_.updatePeerExtInfo(msg);
      return false;
    },
    [](auto&) {
      return true;
    });
}

absl::Status Kex::handleMessage(wire::Message&& msg) noexcept {
  return msg.visit(
    [&](wire::KexInitMessage& msg) {
      if (state_->kex_init_received) {
        return absl::FailedPreconditionError("unexpected KexInit message");
      }

      auto raw_peer_kex_init = msg.encodeTo<bytes>();
      if (!raw_peer_kex_init.ok()) {
        return raw_peer_kex_init.status();
      }

      if (is_server_) {
        state_->magics.client_kex_init = std::move(*raw_peer_kex_init);
      } else {
        state_->magics.server_kex_init = std::move(*raw_peer_kex_init);
      }

      state_->peer_kex = std::move(msg);
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
          auto stat = state_->alg_impl->handleClientSend();
          if (!stat.ok()) {
            return stat.status();
          }
          state_->kex_reply_sent = true;
          return transport_.sendMessageToConnection(*stat).status();
        }
        return absl::OkStatus();
      }
      return absl::OkStatus();
    },
    [&](wire::NewKeysMsg&) {
      if (state_->kex_newkeys_received) {
        return absl::FailedPreconditionError("unexpected NewKeys message received");
      }
      state_->kex_newkeys_received = true;
      if ((state_->is_server && state_->server_supports_ext_info) ||
          (!state_->is_server && state_->client_supports_ext_info)) {
        // this stays active for the next received message only, then is uninstalled
        msg_dispatcher_->installNextMessageMiddleware(this);
      }
      // done
      kex_callbacks_.setKexResult(state_->kex_result);
      return absl::OkStatus();
    },
    [&](const auto&) {
      if (state_->kex_result) {
        return absl::FailedPreconditionError(fmt::format("unexpected message received: {}", msg.msg_type()));
      }
      if (!state_->alg_impl) {
        return absl::FailedPreconditionError(fmt::format("unexpected message received: {}", msg.msg_type()));
      }

      if (is_server_) {
        auto stat = state_->alg_impl->handleServerRecv(msg);
        if (!stat.ok()) {
          return stat;
        }
      } else {
        auto stat = state_->alg_impl->handleClientRecv(msg);
        if (!stat.ok()) {
          return stat;
        }
      }

      state_->kex_result = state_->alg_impl->result();
      state_->alg_impl.reset();
      state_->kex_result->client_supports_ext_info = state_->client_supports_ext_info;
      state_->kex_result->server_supports_ext_info = state_->server_supports_ext_info;

      if (is_server_) {
        if (!state_->kex_reply_sent) {
          auto firstKeyExchange = !state_->session_id.has_value();
          if (firstKeyExchange) {
            state_->session_id = state_->kex_result->exchange_hash;
          }
          state_->kex_result->session_id = state_->session_id.value();

          wire::KexEcdhReplyMsg reply;
          reply.host_key = state_->kex_result->host_key_blob;
          reply.ephemeral_pub_key = state_->kex_result->ephemeral_pub_key;
          reply.signature = state_->kex_result->signature;
          if (auto err = transport_.sendMessageToConnection(reply); !err.ok()) {
            return err.status();
          }
          state_->kex_reply_sent = true;
          // don't return yet, send newkeys first
        }

        if (!state_->kex_newkeys_sent) {
          if (auto err = transport_.sendMessageToConnection(wire::NewKeysMsg{}); !err.ok()) {
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
          state_->session_id = state_->kex_result->exchange_hash;
        }
        state_->kex_result->session_id = state_->session_id.value();

        if (auto err = transport_.sendMessageToConnection(wire::NewKeysMsg{}); !err.ok()) {
          return err.status();
        }
        state_->kex_newkeys_sent = true;
      }
      return absl::OkStatus();
    });
}

absl::StatusOr<Algorithms> Kex::negotiateAlgorithms() noexcept {
  if (is_server_) {
    state_->client_supports_ext_info = absl::c_contains(*state_->peer_kex.kex_algorithms, "ext-info-c");
    state_->server_supports_ext_info = true;
    state_->kex_strict = absl::c_contains(*state_->peer_kex.kex_algorithms, "kex-strict-c-v00@openssh.com");
  } else {
    state_->client_supports_ext_info = true;
    state_->server_supports_ext_info = absl::c_contains(*state_->peer_kex.kex_algorithms, "ext-info-s");
    state_->kex_strict = absl::c_contains(*state_->peer_kex.kex_algorithms, "kex-strict-s-v00@openssh.com");
  }

  if (is_server_) {
    string_list common;
    absl::c_set_union(*state_->peer_kex.server_host_key_algorithms, rsaSha2256HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      state_->kex_rsa_sha2_256_supported = true;
    }
    common.clear();
    absl::c_set_union(*state_->peer_kex.server_host_key_algorithms, rsaSha2512HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      state_->kex_rsa_sha2_512_supported = true;
    }
  }

  // logic below is translated from go ssh/common.go findAgreedAlgorithms
  Algorithms result{};
  {
    auto common_kex =
      findCommon("key exchange", state_->peer_kex.kex_algorithms, state_->our_kex.kex_algorithms);
    if (!common_kex.ok()) {
      return common_kex.status();
    }
    result.kex = *common_kex;

    // RFC8308 section 2.2
    if (invalid_key_exchange_methods.contains(result.kex)) {
      return absl::InvalidArgumentError(
        fmt::format("negotiated an invalid key exchange method: {}", result.kex));
    }
  }
  {
    auto common_host_key = findCommon("host key", state_->peer_kex.server_host_key_algorithms,
                                      state_->our_kex.server_host_key_algorithms);
    if (!common_host_key.ok()) {
      return common_host_key.status();
    }
    result.host_key = *common_host_key;
  }

  DirectionAlgorithms* stoc = is_server_ ? &result.w : &result.r;
  DirectionAlgorithms* ctos = is_server_ ? &result.r : &result.w;

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
    if (hostKey == nullptr) {
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
const host_keypair_t* Kex::getHostKey(const std::string& alg) {
  auto pktype = sshkey_type_from_name(alg.c_str());

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

absl::Status Kex::loadSshKeyPair(const std::string& priv_key_path, const std::string& pub_key_path) {
  auto priv = openssh::SSHKey::fromPrivateKeyFile(priv_key_path);
  if (!priv.ok()) {
    return priv.status();
  }
  auto pub = openssh::SSHKey::fromPublicKeyFile(pub_key_path);
  if (!pub.ok()) {
    return pub.status();
  }
  host_keys_.emplace_back(host_keypair_t{
    .priv = std::move(*priv),
    .pub = std::move(*pub),
  });
  return absl::OkStatus();
}

absl::Status Kex::sendKexInit() noexcept {
  wire::KexInitMessage* server_kex_init = &state_->our_kex;
  std::copy(preferredKexAlgos.begin(), preferredKexAlgos.end(),
            std::back_inserter(*server_kex_init->kex_algorithms));
  if (is_server_) {
    server_kex_init->kex_algorithms->push_back("ext-info-s");
    server_kex_init->kex_algorithms->push_back("kex-strict-s-v00@openssh.com");
  } else {
    server_kex_init->kex_algorithms->push_back("ext-info-c");
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

  auto raw_kex_init = server_kex_init->encodeTo<bytes>();
  if (!raw_kex_init.ok()) {
    return raw_kex_init.status();
  }
  if (is_server_) {
    state_->magics.server_kex_init = std::move(*raw_kex_init);
  } else {
    state_->magics.client_kex_init = std::move(*raw_kex_init);
  }

  if (auto err = transport_.sendMessageToConnection(*server_kex_init); !err.ok()) {
    return err.status();
  }
  return absl::OkStatus();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec