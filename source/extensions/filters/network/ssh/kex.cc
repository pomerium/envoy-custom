#include "source/extensions/filters/network/ssh/kex.h"

#include <memory>

#include "openssl/rand.h"

#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/sshkey.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

Kex::Kex(TransportCallbacks& transport_callbacks, KexCallbacks& kex_callbacks, KexMode mode)
    : transport_(transport_callbacks), kex_callbacks_(kex_callbacks),
      is_server_(mode == KexMode::Server) {
  THROW_IF_NOT_OK(loadHostKeys());
}

void Kex::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::KexInit, this);
  msg_dispatcher_ = dispatcher;
}

void Kex::setVersionStrings(const std::string& ours, const std::string& peer) {
  if (is_server_) {
    server_version_ = ours;
    client_version_ = peer;
  } else {
    server_version_ = peer;
    client_version_ = ours;
  }
}

absl::StatusOr<MiddlewareResult> Kex::IncorrectGuessMsgHandler::interceptMessage(wire::Message& msg) {
  if (self.is_server_) {
    if (!self.pending_state_->alg_impl->clientInitMessageTypes().contains(msg.msg_type())) {
      return absl::FailedPreconditionError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  } else {
    if (!self.pending_state_->alg_impl->serverReplyMessageTypes().contains(msg.msg_type())) {
      return absl::FailedPreconditionError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  }
  return Break | UninstallSelf;
}

absl::StatusOr<MiddlewareResult> Kex::KexAlgMsgHandler::interceptMessage(wire::Message& msg) {
  if (self.is_server_) {
    if (!self.pending_state_->alg_impl->clientInitMessageTypes().contains(msg.msg_type())) {
      return absl::FailedPreconditionError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  } else {
    if (!self.pending_state_->alg_impl->serverReplyMessageTypes().contains(msg.msg_type())) {
      return absl::FailedPreconditionError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  }

  KexResultSharedPtr pendingKexResult;
  if (self.is_server_) {
    auto res = self.pending_state_->alg_impl->handleServerRecv(msg);
    if (!res.ok()) {
      return statusf("key exchange failed: {}", res.status());
    }
    if (!res->has_value()) {
      // key exchange not complete yet
      return Break;
    }
    pendingKexResult = res->value();
  } else {
    auto res = self.pending_state_->alg_impl->handleClientRecv(msg);
    if (!res.ok()) {
      return statusf("key exchange failed: {}", res.status());
    }
    if (!res->has_value()) {
      // key exchange not complete yet
      return Break;
    }
    pendingKexResult = res->value();
  }

  pendingKexResult->client_supports_ext_info = self.pending_state_->client_supports_ext_info;
  pendingKexResult->server_supports_ext_info = self.pending_state_->server_supports_ext_info;

  if (self.isInitialKex()) {
    pendingKexResult->session_id = pendingKexResult->exchange_hash;
  } else {
    // session id stays the same after key re-exchange
    pendingKexResult->session_id = self.active_state_->kex_result->session_id;
  }

  self.pending_state_->kex_result = std::move(pendingKexResult);

  if (self.is_server_) {
    auto reply = self.pending_state_->alg_impl->buildServerReply(*self.pending_state_->kex_result);
    if (!reply.ok()) {
      return reply.status();
    }
    if (auto err = self.transport_.sendMessageDirect(std::move(reply).value()); !err.ok()) {
      return err.status();
    }
    // don't return yet, send newkeys first
  }

  if (auto stat = self.sendNewKeysMsg(); !stat.ok()) {
    return stat;
  }
  self.msg_dispatcher_->installMiddleware(&self.msg_handler_new_keys_);
  return Break | UninstallSelf;
}

absl::StatusOr<MiddlewareResult> Kex::NewKeysMsgHandler::interceptMessage(wire::Message& msg) {
  if (msg.msg_type() != wire::SshMessageType::NewKeys) {
    return absl::FailedPreconditionError(fmt::format("key exchange error: expected NewKeys, received {}", msg.msg_type()));
  }

  if (self.isInitialKex()) {
    // ExtInfo is only sent after the initial NewKeys (RFC8308 § 2.4)
    if ((self.is_server_ && self.pending_state_->server_supports_ext_info) ||
        (!self.is_server_ && self.pending_state_->client_supports_ext_info)) {
      // this stays active for the next received message only, then is uninstalled
      self.msg_dispatcher_->installMiddleware(&self.msg_handler_ext_info_);
    }
  }

  // done
  self.onNewKeysMsgReceived();
  return Break | UninstallSelf;
}

absl::StatusOr<MiddlewareResult> Kex::ExtInfoMsgHandler::interceptMessage(wire::Message& msg) {
  return msg.visit(
    [&](wire::ExtInfoMsg& msg) {
      self.transport_.updatePeerExtInfo(msg);
      return Break | UninstallSelf;
    },
    [](auto&) {
      return Continue | UninstallSelf;
    });
}

absl::Status Kex::handleMessage(wire::Message&& msg) noexcept {
  return msg.visit(
    [&](wire::KexInitMsg& msg) {
      if (pending_state_) {
        return absl::FailedPreconditionError("unexpected KexInit message received");
      }
      pending_state_ = std::make_unique<KexState>();
      auto initial_kex = isInitialKex();
      kex_callbacks_.onKexStarted(initial_kex);

      auto raw_peer_kex_init = encodeTo<bytes>(msg);
      if (!raw_peer_kex_init.ok()) {
        return raw_peer_kex_init.status();
      }

      // set up magics
      pending_state_->magics.client_version = client_version_;
      pending_state_->magics.server_version = server_version_;
      if (is_server_) {
        pending_state_->magics.client_kex_init = std::move(*raw_peer_kex_init);
      } else {
        pending_state_->magics.server_kex_init = std::move(*raw_peer_kex_init);
      }
      pending_state_->peer_kex = std::move(msg);

      if (auto err = sendKexInitMsg(initial_kex); !err.ok()) {
        return err;
      }

      if (auto algs = negotiateAlgorithms(initial_kex); !algs.ok()) {
        return algs.status();
      } else {
        pending_state_->negotiated_algorithms = *algs;
      }

      auto algImpl = newAlgorithmImpl();
      if (!algImpl.ok()) {
        return algImpl.status();
      }

      if (pending_state_->peer_kex.first_kex_packet_follows) {
        if ((pending_state_->peer_kex.kex_algorithms[0] != pending_state_->our_kex.kex_algorithms[0]) ||
            (pending_state_->peer_kex.server_host_key_algorithms[0] !=
             pending_state_->our_kex.server_host_key_algorithms[0])) {
          msg_dispatcher_->installMiddleware(&msg_handler_incorrect_guess_);
        }
      }

      pending_state_->alg_impl = std::move(*algImpl);

      if (!is_server_) {
        auto clientInit = pending_state_->alg_impl->buildClientInit();
        if (!clientInit.ok()) {
          return clientInit.status();
        }
        if (auto stat = transport_.sendMessageDirect(std::move(clientInit).value()); !stat.ok()) {
          return stat.status();
        }
      }
      msg_dispatcher_->installMiddleware(&msg_handler_kex_alg_);
      return absl::OkStatus();
    },
    [&](const auto&) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    });
}

absl::Status Kex::sendKexInitMsg(bool initial_kex) noexcept {
  wire::KexInitMsg* server_kex_init = &pending_state_->our_kex;
  server_kex_init->kex_algorithms = preferredKexAlgos;

  if (initial_kex) {
    if (is_server_) {
      server_kex_init->kex_algorithms->push_back("ext-info-s");
      server_kex_init->kex_algorithms->push_back("kex-strict-s-v00@openssh.com");
    } else {
      server_kex_init->kex_algorithms->push_back("ext-info-c");
      server_kex_init->kex_algorithms->push_back("kex-strict-c-v00@openssh.com");
    }
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
    server_kex_init->server_host_key_algorithms->append_range(algs);
  }

  auto raw_kex_init = encodeTo<bytes>(*server_kex_init);
  if (!raw_kex_init.ok()) {
    return raw_kex_init.status();
  }
  if (is_server_) {
    pending_state_->magics.server_kex_init = std::move(*raw_kex_init);
  } else {
    pending_state_->magics.client_kex_init = std::move(*raw_kex_init);
  }

  if (auto r = transport_.sendMessageDirect(auto(*server_kex_init)); !r.ok()) {
    return r.status();
  }

  // notify transport to pause message forwarding
  kex_callbacks_.onKexInitMsgSent();
  return absl::OkStatus();
}

void Kex::onNewKeysMsgReceived() {
  // NB: order is important here

  // reset sequence number upon receiving NewKeys
  ENVOY_LOG(debug, "resetting read sequence number (prev: {})", *transport_.getConnectionState().seq_read);
  *transport_.getConnectionState().seq_read = 0;

  bool initial = isInitialKex(); // checks active_state_

  // promote pending state -> active state, deleting the previous active state
  active_state_ = std::move(pending_state_);

  kex_callbacks_.onKexCompleted(active_state_->kex_result, initial);
}

absl::Status Kex::sendNewKeysMsg() {
  // NB: order is important here

  // send the NewKeys message
  if (auto err = transport_.sendMessageDirect(wire::NewKeysMsg{}); !err.ok()) {
    return err.status();
  }

  // reset write sequence number after sending NewKeys
  ENVOY_LOG(debug, "resetting write sequence number (prev: {})", *transport_.getConnectionState().seq_write);
  *transport_.getConnectionState().seq_write = 0;

  // notify transport to resume message forwarding if necessary (using new sequence numbers)
  return kex_callbacks_.onNewKeysMsgSent();
}

absl::StatusOr<Algorithms> Kex::negotiateAlgorithms(bool initial_kex) noexcept {
  if (initial_kex) {
    if (is_server_) {
      pending_state_->client_supports_ext_info = absl::c_contains(*pending_state_->peer_kex.kex_algorithms, "ext-info-c");
      pending_state_->server_supports_ext_info = true;
      pending_state_->kex_strict = absl::c_contains(*pending_state_->peer_kex.kex_algorithms, "kex-strict-c-v00@openssh.com");
    } else {
      pending_state_->client_supports_ext_info = true;
      pending_state_->server_supports_ext_info = absl::c_contains(*pending_state_->peer_kex.kex_algorithms, "ext-info-s");
      pending_state_->kex_strict = absl::c_contains(*pending_state_->peer_kex.kex_algorithms, "kex-strict-s-v00@openssh.com");
    }
  } else {
    pending_state_->client_supports_ext_info = active_state_->client_supports_ext_info;
    pending_state_->server_supports_ext_info = active_state_->server_supports_ext_info;
    pending_state_->kex_strict = active_state_->kex_strict;
  }

  if (is_server_) {
    string_list common;
    absl::c_set_union(*pending_state_->peer_kex.server_host_key_algorithms, rsaSha2256HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      pending_state_->kex_rsa_sha2_256_supported = true;
    }
    common.clear();
    absl::c_set_union(*pending_state_->peer_kex.server_host_key_algorithms, rsaSha2512HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      pending_state_->kex_rsa_sha2_512_supported = true;
    }
  }

  wire::KexInitMsg& client_kex = is_server_ ? pending_state_->peer_kex : pending_state_->our_kex;
  wire::KexInitMsg& server_kex = is_server_ ? pending_state_->our_kex : pending_state_->peer_kex;

  // logic below is translated from go ssh/common.go findAgreedAlgorithms
  Algorithms result{};
  {
    auto common_kex = findCommon("key exchange",
                                 client_kex.kex_algorithms,
                                 server_kex.kex_algorithms);
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
    auto common_host_key = findCommon("host key",
                                      client_kex.server_host_key_algorithms,
                                      server_kex.server_host_key_algorithms);
    if (!common_host_key.ok()) {
      return common_host_key.status();
    }
    result.host_key = *common_host_key;
  }

  DirectionAlgorithms* stoc = is_server_ ? &result.w : &result.r;
  DirectionAlgorithms* ctos = is_server_ ? &result.r : &result.w;

  {
    auto common_cipher = findCommon("client to server cipher",
                                    client_kex.encryption_algorithms_client_to_server,
                                    server_kex.encryption_algorithms_client_to_server);
    if (!common_cipher.ok()) {
      return common_cipher.status();
    }
    ctos->cipher = *common_cipher;
  }
  {
    auto common_cipher = findCommon("server to client cipher",
                                    client_kex.encryption_algorithms_server_to_client,
                                    server_kex.encryption_algorithms_server_to_client);
    if (!common_cipher.ok()) {
      return common_cipher.status();
    }
    stoc->cipher = *common_cipher;
  }

  if (!aeadCiphers.contains(ctos->cipher)) {
    auto common_mac =
      findCommon("client to server MAC",
                 client_kex.mac_algorithms_client_to_server,
                 server_kex.mac_algorithms_client_to_server);
    if (!common_mac.ok()) {
      return common_mac.status();
    }
    ctos->mac = *common_mac;
  }

  if (!aeadCiphers.contains(stoc->cipher)) {
    auto common_mac =
      findCommon("server to client MAC",
                 client_kex.mac_algorithms_server_to_client,
                 server_kex.mac_algorithms_server_to_client);
    if (!common_mac.ok()) {
      return common_mac.status();
    }
    stoc->mac = *common_mac;
  }

  {
    auto common_compression = findCommon("client to server compression",
                                         client_kex.compression_algorithms_client_to_server,
                                         server_kex.compression_algorithms_client_to_server);
    if (!common_compression.ok()) {
      return common_compression.status();
    }
    ctos->compression = *common_compression;
  }
  {
    auto common_compression = findCommon("server to client compression",
                                         client_kex.compression_algorithms_server_to_client,
                                         server_kex.compression_algorithms_server_to_client);
    if (!common_compression.ok()) {
      return common_compression.status();
    }
    stoc->compression = *common_compression;
  }

  return result;
}

absl::StatusOr<std::string> Kex::findCommon(std::string_view what,
                                            const string_list& client,
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
  if (pending_state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256 ||
      pending_state_->negotiated_algorithms.kex == kexAlgoCurve25519SHA256LibSSH) {
    auto hostKey = pickHostKey(pending_state_->negotiated_algorithms.host_key);
    if (hostKey == nullptr) {
      return absl::AbortedError(fmt::format("no matching host key for algorithm: {}",
                                            pending_state_->negotiated_algorithms.host_key));
    }
    return std::make_unique<Curve25519Sha256KexAlgorithm>(&pending_state_->magics,
                                                          &pending_state_->negotiated_algorithms, hostKey);
  }
  return absl::UnimplementedError(
    fmt::format("unsupported key exchange algorithm: {}", pending_state_->negotiated_algorithms.kex));
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
const host_keypair_t* Kex::getHostKey(sshkey_types pktype) {
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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec