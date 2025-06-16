#include "source/extensions/filters/network/ssh/kex.h"

#include "openssl/rand.h"

#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

Kex::Kex(TransportCallbacks& transport_callbacks,
         KexCallbacks& kex_callbacks,
         KexAlgorithmFactoryRegistry& algorithm_factories,
         DirectionalPacketCipherFactoryRegistry& cipher_factories,
         KexMode mode)
    : transport_(transport_callbacks),
      kex_callbacks_(kex_callbacks),
      algorithm_factories_(algorithm_factories),
      cipher_factories_(cipher_factories),
      is_server_(mode == KexMode::Server) {
}

void Kex::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::KexInit, this);
  msg_dispatcher_ = dispatcher;
}

void Kex::onVersionExchangeCompleted(const bytes& server_version,
                                     const bytes& client_version,
                                     const bytes& banner) {
  server_version_ = server_version;
  client_version_ = client_version;
  version_exchange_banner_ = banner;
  kex_callbacks_.onVersionExchangeCompleted(server_version, client_version, banner);
}

void Kex::setHostKeys(std::vector<openssh::SSHKeyPtr> host_keys) {
  host_keys_ = std::move(host_keys);
}

absl::StatusOr<MiddlewareResult> Kex::IncorrectGuessMsgHandler::interceptMessage(wire::Message& msg) {
  if (self.is_server_) {
    if (!self.pending_state_->alg_impl->clientInitMessageTypes().contains(msg.msg_type())) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  } else {
    if (!self.pending_state_->alg_impl->serverReplyMessageTypes().contains(msg.msg_type())) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  }
  return Break | UninstallSelf;
}

absl::StatusOr<MiddlewareResult> Kex::KexAlgMsgHandler::interceptMessage(wire::Message& msg) {
  if (self.is_server_) {
    if (!self.pending_state_->alg_impl->clientInitMessageTypes().contains(msg.msg_type())) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    }
  } else {
    if (!self.pending_state_->alg_impl->serverReplyMessageTypes().contains(msg.msg_type())) {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
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
    if (auto err = self.transport_.sendMessageDirect(
          self.pending_state_->alg_impl->buildServerReply(*self.pending_state_->kex_result));
        !err.ok()) {
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
    // https://datatracker.ietf.org/doc/html/rfc8308#section-2.4
    // We always signal support for ext-info, so the peer is always given the opportunity to send
    // an ExtInfo message after it sends its initial NewKeys message.
    self.msg_dispatcher_->installMiddleware(&self.msg_handler_ext_info_);
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
        // The only way to get here is if either:
        // a) we initiated the key exchange but have not received a response yet.
        // b) we failed to send our KexInit message, but did not propagate the error correctly,
        //    causing an in-flight message containing the peer KexInit to be incorrectly delivered.
        //
        // It shouldn't be possible to receive two KexInit messages *here* since
        // a second KexInit message would be caught by one of the middlewares.
        RELEASE_ASSERT(pending_state_->kex_init_sent && !pending_state_->kex_init_received,
                       "bug: unexpected KexInitMsg received");
      } else {
        pending_state_ = std::make_unique<KexState>();
      }
      pending_state_->kex_init_received = true;
      auto initial_kex = isInitialKex();
      kex_callbacks_.onKexStarted(initial_kex);

      auto rawPeerKexInit = encodeTo<bytes>(msg);
      RELEASE_ASSERT(rawPeerKexInit.ok(), "bug: failed to encode KexInit");

      // set up magics
      pending_state_->magics.client_version = client_version_;
      pending_state_->magics.server_version = server_version_;
      if (is_server_) {
        pending_state_->magics.client_kex_init = std::move(*rawPeerKexInit);
      } else {
        pending_state_->magics.server_kex_init = std::move(*rawPeerKexInit);
      }
      pending_state_->peer_kex = std::move(msg);

      if (!pending_state_->kex_init_sent) {
        if (auto err = sendKexInitMsg(initial_kex); !err.ok()) {
          return err;
        }
      }

      if (auto algs = findAgreedAlgorithms(initial_kex); !algs.ok()) {
        return algs.status();
      } else {
        pending_state_->negotiated_algorithms = *algs;
      }

      if (pending_state_->peer_kex.first_kex_packet_follows) {
        if ((pending_state_->peer_kex.kex_algorithms[0] !=
             pending_state_->our_kex.kex_algorithms[0]) ||
            (pending_state_->peer_kex.server_host_key_algorithms[0] !=
             pending_state_->our_kex.server_host_key_algorithms[0])) {
          msg_dispatcher_->installMiddleware(&msg_handler_incorrect_guess_);
        }
      }

      pending_state_->alg_impl = createKexAlgorithm();

      if (!is_server_) {
        if (auto stat = transport_.sendMessageDirect(
              pending_state_->alg_impl->buildClientInit());
            !stat.ok()) {
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
  wire::KexInitMsg* kexInit = &pending_state_->our_kex;
  kexInit->kex_algorithms = algorithm_factories_.namesByPriority();

  if (initial_kex) {
    if (is_server_) {
      kexInit->kex_algorithms->push_back("ext-info-s");
      kexInit->kex_algorithms->push_back("kex-strict-s-v00@openssh.com");
    } else {
      kexInit->kex_algorithms->push_back("ext-info-c");
      kexInit->kex_algorithms->push_back("kex-strict-c-v00@openssh.com");
    }
  }
  kexInit->encryption_algorithms_client_to_server = cipher_factories_.namesByPriority();
  kexInit->encryption_algorithms_server_to_client = cipher_factories_.namesByPriority();
  kexInit->mac_algorithms_client_to_server = SupportedMACs;
  kexInit->mac_algorithms_server_to_client = SupportedMACs;
  kexInit->compression_algorithms_client_to_server = {"none"s};
  kexInit->compression_algorithms_server_to_client = {"none"s};
  RAND_bytes(kexInit->cookie->data(), sizeof(kexInit->cookie));
  for (const auto& hostKey : host_keys_) {
    kexInit->server_host_key_algorithms->append_range(hostKey->signatureAlgorithmsForKeyType());
  }

  auto rawKexInit = encodeTo<bytes>(*kexInit);
  RELEASE_ASSERT(rawKexInit.ok(), "bug: failed to encode KexInit");

  if (is_server_) {
    pending_state_->magics.server_kex_init = std::move(*rawKexInit);
  } else {
    pending_state_->magics.client_kex_init = std::move(*rawKexInit);
  }

  // notify transport to pause message forwarding
  // this is called before actually sending the message to prevent recursively initiating a
  // key re-exchange
  kex_callbacks_.onKexInitMsgSent();

  if (auto r = transport_.sendMessageDirect(auto(*kexInit)); !r.ok()) {
    return r.status();
  }
  // Important: kex_init_sent must be set after sendMessageDirect, in case it fails. This state
  // is checked when receiving the peer's KexInit.
  pending_state_->kex_init_sent = true;

  return absl::OkStatus();
}

void Kex::onNewKeysMsgReceived() {
  // NB: order is important here

  // reset sequence number upon receiving NewKeys
  auto prev = transport_.resetReadSequenceNumber();
  ENVOY_LOG(debug, "ssh [{}]: resetting read sequence number (prev: {})",
            is_server_ ? "server" : "client", prev);

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
  auto prev = transport_.resetWriteSequenceNumber();
  ENVOY_LOG(debug, "ssh [{}]: resetting write sequence number (prev: {})",
            is_server_ ? "server" : "client", prev);

  return absl::OkStatus();
}

// Adapted from findAgreedAlgorithms in https://github.com/golang/crypto/blob/master/ssh/common.go
// which is licensed under a BSD-style license (Copyright 2011 The Go Authors).
absl::StatusOr<Algorithms> Kex::findAgreedAlgorithms(bool initial_kex) const noexcept {
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

  if (!pending_state_->kex_strict) {
    return absl::InvalidArgumentError("strict key exchange mode is required");
  }

  if (is_server_) {
    string_list common;
    absl::c_set_union(*pending_state_->peer_kex.server_host_key_algorithms, RsaSha2256HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      pending_state_->kex_rsa_sha2_256_supported = true;
    }
    common.clear();
    absl::c_set_union(*pending_state_->peer_kex.server_host_key_algorithms, RsaSha2512HostKeyAlgs,
                      std::back_inserter(common));
    if (!common.empty()) {
      pending_state_->kex_rsa_sha2_512_supported = true;
    }
  }

  wire::KexInitMsg& client_kex = is_server_ ? pending_state_->peer_kex : pending_state_->our_kex;
  wire::KexInitMsg& server_kex = is_server_ ? pending_state_->our_kex : pending_state_->peer_kex;

  Algorithms result{};

  if (auto alg = findCommon("key exchange",
                            client_kex.kex_algorithms,
                            server_kex.kex_algorithms);
      !alg.ok()) {
    return alg.status();
  } else {
    result.kex = *alg;
  }

  // RFC8308 § 2.2
  if (InvalidKeyExchangeMethods.contains(result.kex)) {
    return absl::InvalidArgumentError(
      fmt::format("negotiated an invalid key exchange method: {}", result.kex));
  }

  if (auto alg = findCommon("host key",
                            client_kex.server_host_key_algorithms,
                            server_kex.server_host_key_algorithms);
      !alg.ok()) {
    return alg.status();
  } else {
    result.host_key = *alg;
  }

  if (auto alg = findCommon("client to server cipher",
                            client_kex.encryption_algorithms_client_to_server,
                            server_kex.encryption_algorithms_client_to_server);
      !alg.ok()) {
    return alg.status();
  } else {
    result.client_to_server.cipher = *alg;
  }

  if (auto alg = findCommon("server to client cipher",
                            client_kex.encryption_algorithms_server_to_client,
                            server_kex.encryption_algorithms_server_to_client);
      !alg.ok()) {
    return alg.status();
  } else {
    result.server_to_client.cipher = *alg;
  }

  if (!AEADCiphers.contains(result.client_to_server.cipher)) {
    if (auto alg =
          findCommon("client to server MAC",
                     client_kex.mac_algorithms_client_to_server,
                     server_kex.mac_algorithms_client_to_server);
        !alg.ok()) {
      return alg.status();
    } else {
      result.client_to_server.mac = *alg;
    }
  }

  if (!AEADCiphers.contains(result.server_to_client.cipher)) {
    if (auto alg = findCommon("server to client MAC",
                              client_kex.mac_algorithms_server_to_client,
                              server_kex.mac_algorithms_server_to_client);
        !alg.ok()) {
      return alg.status();
    } else {
      result.server_to_client.mac = *alg;
    }
  }

  if (auto alg = findCommon("client to server compression",
                            client_kex.compression_algorithms_client_to_server,
                            server_kex.compression_algorithms_client_to_server);
      !alg.ok()) {
    return alg.status();
  } else {
    result.client_to_server.compression = *alg;
  }

  if (auto alg = findCommon("server to client compression",
                            client_kex.compression_algorithms_server_to_client,
                            server_kex.compression_algorithms_server_to_client);
      !alg.ok()) {
    return alg.status();
  } else {
    result.server_to_client.compression = *alg;
  }

  if (!client_kex.languages_client_to_server->empty()) {
    return absl::UnimplementedError("unsupported client to server language");
  }

  if (!client_kex.languages_server_to_client->empty()) {
    return absl::UnimplementedError("unsupported server to client language");
  }

  return result;
}

absl::StatusOr<std::string> Kex::findCommon(const std::string_view what,
                                            const string_list& client,
                                            const string_list& server) const {
  for (const auto& c : client) {
    for (const auto& s : server) {
      if (c == s) {
        return c;
      }
    }
  }
  return absl::InvalidArgumentError(fmt::format(
    "no common algorithm for {}; client offered: {}; server offered: {}", what, client, server));
}

std::unique_ptr<KexAlgorithm> Kex::createKexAlgorithm() const {
  auto hostKey = pickHostKey(pending_state_->negotiated_algorithms.host_key);
  ASSERT(hostKey != nullptr);
  return algorithm_factories_
    .factoryForName(pending_state_->negotiated_algorithms.kex)
    ->create(&pending_state_->magics,
             &pending_state_->negotiated_algorithms,
             hostKey);
}

const openssh::SSHKey* Kex::pickHostKey(std::string_view signature_algorithm) const {
  for (const auto& keypair : host_keys_) {
    for (const auto& keyAlg : keypair->signatureAlgorithmsForKeyType()) {
      if (signature_algorithm == keyAlg) {
        return keypair.get();
      }
    }
  }
  return nullptr;
}
const openssh::SSHKey* Kex::getHostKey(sshkey_types key_type) const {
  for (const auto& keypair : host_keys_) {
    if (keypair->keyType() == key_type) {
      return keypair.get();
    }
  }
  return nullptr;
}

absl::Status Kex::initiateKex() {
  if (pending_state_) {
    IS_ENVOY_BUG("bug: initiateKex called during key exchange");
    return absl::InternalError("bug: initiateKex called during key exchange");
  }
  pending_state_ = std::make_unique<KexState>();
  return sendKexInitMsg(isInitialKex());
}

namespace {
void generateKeyMaterial(bytes& out, char tag, KexResult* kex_result) {
  // translated from go ssh/transport.go
  bytes digestsSoFar;

  using namespace std::placeholders;
  while (out.size() < out.capacity()) {
    openssh::Hash hash(kex_result->hash);
    bytes encoded_k;
    kex_result->encodeSharedSecret(encoded_k);
    hash.write(encoded_k);
    hash.write(kex_result->exchange_hash);
    if (digestsSoFar.size() == 0) {
      hash.write(tag);
      hash.write(kex_result->session_id);
    } else {
      hash.write(digestsSoFar);
    }
    bytes digest = hash.sum();
    auto toCopy = std::min(out.capacity() - out.size(), digest.size());
    if (toCopy > 0) {
      std::copy_n(digest.begin(), toCopy, std::back_inserter(out));
      std::copy(digest.begin(), digest.end(), std::back_inserter(digestsSoFar));
    }
  }
}
} // namespace

std::unique_ptr<PacketCipher>
makePacketCipherFromKexResult(DirectionalPacketCipherFactoryRegistry& cipher_factories,
                              DirectionTags d_read,
                              DirectionTags d_write,
                              KexMode mode,
                              KexResult* kex_result) {
  RELEASE_ASSERT(!kex_result->session_id.empty(), "session id unset");
  const auto& readAlgs = readDirectionAlgsForMode(kex_result->algorithms, mode);
  const auto& writeAlgs = writeDirectionAlgsForMode(kex_result->algorithms, mode);
  auto readFactory = cipher_factories.factoryForName(readAlgs.cipher);
  auto writeFactory = cipher_factories.factoryForName(writeAlgs.cipher);

  DerivedKeys read;
  read.iv.reserve(readFactory->ivSize());
  generateKeyMaterial(read.iv, d_read.iv_tag, kex_result);
  read.key.reserve(readFactory->keySize());
  generateKeyMaterial(read.key, d_read.key_tag, kex_result);
  if (!readAlgs.mac.empty()) {
    read.mac.reserve(MACKeySizes.at(readAlgs.mac));
    generateKeyMaterial(read.mac, d_read.mac_key_tag, kex_result);
  }

  DerivedKeys write;
  write.iv.reserve(writeFactory->ivSize());
  generateKeyMaterial(write.iv, d_write.iv_tag, kex_result);
  write.key.reserve(writeFactory->keySize());
  generateKeyMaterial(write.key, d_write.key_tag, kex_result);
  if (!writeAlgs.mac.empty()) {
    write.mac.reserve(MACKeySizes.at(writeAlgs.mac));
    generateKeyMaterial(write.mac, d_write.mac_key_tag, kex_result);
  }

  return std::make_unique<PacketCipher>(readFactory->create(read, readAlgs, openssh::CipherMode::Read),
                                        writeFactory->create(write, writeAlgs, openssh::CipherMode::Write));
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec