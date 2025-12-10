#include "source/extensions/filters/network/ssh/kex_alg_curve25519.h"

#include <algorithm>

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<std::optional<KexResultSharedPtr>> Curve25519Sha256KexAlgorithm::handleServerRecv(wire::Message& msg) {
  return msg.visit(
    [&](opt_ref<wire::KexEcdhInitMsg> opt_msg) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid key exchange init");
      }
      auto& msg = opt_msg->get();
      if (auto sz = msg.client_pub_key->size(); sz != X25519_PUBLIC_VALUE_LEN) {
        return absl::InvalidArgumentError(
          fmt::format("invalid peer public key size (expected 32, got {})", sz));
      }

      Curve25519Keypair server_keypair{};
      X25519_keypair(server_keypair.pub.data(), server_keypair.priv.data());

      fixed_bytes<X25519_SHARED_KEY_LEN> shared_secret{};
      // NB: this function validates that the output is not all-zeros
      if (X25519(shared_secret.data(),
                 server_keypair.priv.data(),
                 std::span{*msg.client_pub_key}.first<X25519_PUBLIC_VALUE_LEN>().data()) == 0) {
        return absl::InvalidArgumentError("x25519 error");
      }
      server_keypair.priv.fill(0);

      auto blob = signer_->toPublicKeyBlob();
      auto res = computeServerResult(blob, *msg.client_pub_key, server_keypair.pub,
                                     std::exchange(shared_secret, {}));
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
      if (auto sz = msg.ephemeral_pub_key->size(); sz != X25519_PUBLIC_VALUE_LEN) {
        return absl::InvalidArgumentError(
          fmt::format("invalid peer public key size (expected 32, got {})", sz));
      }

      fixed_bytes<X25519_SHARED_KEY_LEN> shared_secret{};
      if (!X25519(shared_secret.data(), client_keypair_.priv.data(),
                  std::span{*msg.ephemeral_pub_key}.first<X25519_PUBLIC_VALUE_LEN>().data())) {
        return absl::InvalidArgumentError("x25519 error");
      }
      client_keypair_.priv.fill(0);

      auto res = computeClientResult(*msg.host_key, client_keypair_.pub, *msg.ephemeral_pub_key,
                                     std::exchange(shared_secret, {}), *msg.signature);
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
  X25519_keypair(client_keypair_.pub.data(), client_keypair_.priv.data());
  return wire::KexEcdhInitMsg{
    .client_pub_key = to_bytes(client_keypair_.pub),
  };
}

const KexAlgorithm::MessageTypeList& Curve25519Sha256KexAlgorithm::clientInitMessageTypes() const {
  static MessageTypeList list{wire::KexEcdhInitMsg::type};
  return list;
}

wire::Message Curve25519Sha256KexAlgorithm::buildServerReply(const KexResult& res) {
  return wire::KexEcdhReplyMsg{
    .host_key = res.host_key_blob,
    .ephemeral_pub_key = res.server_ephemeral_pub_key,
    .signature = res.signature,
  };
}

const KexAlgorithm::MessageTypeList& Curve25519Sha256KexAlgorithm::serverReplyMessageTypes() const {
  static MessageTypeList list{wire::KexEcdhReplyMsg::type};
  return list;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec