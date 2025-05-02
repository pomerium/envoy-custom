#include "source/extensions/filters/network/ssh/kex_alg.h"

#include <algorithm>

#include "openssl/curve25519.h"

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/kex.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<std::optional<KexResultSharedPtr>> Curve25519Sha256KexAlgorithm::handleServerRecv(wire::Message& msg) {
  return msg.visit(
    [&](opt_ref<wire::KexEcdhInitMsg> opt_msg) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid key exchange init");
      }
      auto& msg = opt_msg->get();
      if (auto sz = msg.client_pub_key->size(); sz != 32) {
        return absl::InvalidArgumentError(
          fmt::format("invalid peer public key size (expected 32, got {})", sz));
      }
      fixed_bytes<32> client_pub_key;
      std::copy_n(msg.client_pub_key->begin(), 32, client_pub_key.begin());

      Curve25519Keypair server_keypair;
      kexc25519_keygen(server_keypair.priv.data(), server_keypair.pub.data());

      fixed_bytes<32> shared_secret;
      // NB: this function validates that the output is not all-zeros
      if (X25519(shared_secret.data(), server_keypair.priv.data(), client_pub_key.data()) == 0) {
        return absl::InvalidArgumentError("x25519 error");
      }

      auto blob = signer_->toPublicKeyBlob();
      if (!blob.ok()) {
        return statusf("error converting public key to blob: {}", blob.status());
      }
      auto res = computeServerResult(*blob, client_pub_key, server_keypair.pub, shared_secret);
      if (!res.ok()) {
        return statusf("error computing server result: {}", res.status());
      }
      return *res;
    },
    [&msg](auto&) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    });
}

absl::StatusOr<std::optional<KexResultSharedPtr>> Curve25519Sha256KexAlgorithm::handleClientRecv(wire::Message& msg) {
  return msg.visit(
    [&](opt_ref<wire::KexEcdhReplyMsg> opt_msg) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid key exchange reply");
      }
      auto& msg = opt_msg->get();
      if (auto sz = msg.ephemeral_pub_key->size(); sz != 32) {
        return absl::InvalidArgumentError(
          fmt::format("invalid peer public key size (expected 32, got {})", sz));
      }

      fixed_bytes<32> server_pub_key;
      std::copy_n(msg.ephemeral_pub_key->begin(), 32, server_pub_key.begin());

      fixed_bytes<32> shared_secret;
      if (!X25519(shared_secret.data(), client_keypair_.priv.data(), server_pub_key.data())) {
        return absl::InvalidArgumentError("x25519 error");
      }

      auto res = computeClientResult(*msg.host_key, client_keypair_.pub, server_pub_key, shared_secret, *msg.signature);
      if (!res.ok()) {
        return res.status();
      }
      return *res;
    },
    [&msg](auto&) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    });
}

wire::Message Curve25519Sha256KexAlgorithm::buildClientInit() {
  Curve25519Keypair client_keypair;
  kexc25519_keygen(client_keypair.priv.data(), client_keypair.pub.data());
  client_keypair_ = client_keypair;
  auto msg = wire::KexEcdhInitMsg{};

  msg.client_pub_key = bytes{client_keypair.pub.begin(), client_keypair.pub.end()};
  return msg;
}

const KexAlgorithm::MessageTypeList& Curve25519Sha256KexAlgorithm::clientInitMessageTypes() const {
  static MessageTypeList list{wire::KexEcdhInitMsg::type};
  return list;
}

wire::Message Curve25519Sha256KexAlgorithm::buildServerReply(const KexResult& res) {
  wire::KexEcdhReplyMsg reply;
  reply.host_key = res.host_key_blob;
  reply.ephemeral_pub_key = res.server_ephemeral_pub_key;
  reply.signature = res.signature;
  return reply;
}

const KexAlgorithm::MessageTypeList& Curve25519Sha256KexAlgorithm::serverReplyMessageTypes() const {
  static MessageTypeList list{wire::KexEcdhReplyMsg::type};
  return list;
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec