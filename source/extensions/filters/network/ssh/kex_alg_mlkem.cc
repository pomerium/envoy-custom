#include "source/extensions/filters/network/ssh/kex_alg_mlkem.h"

#include "openssl/mlkem.h"
#include "openssl/span.h"
#include "openssl/bytestring.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<std::optional<KexResultSharedPtr>> Mlkem768x25519KexAlgorithm::handleServerRecv(wire::Message& msg) {
  return msg.visit(
    [&](opt_ref<wire::KexHybridInitMsg> opt_msg) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid key exchange init");
      }
      auto& msg = opt_msg->get();

      const size_t expectedClientInitSize = MLKEM768_PUBLIC_KEY_BYTES + X25519_PUBLIC_VALUE_LEN;
      if (msg.client_init->size() != expectedClientInitSize) {
        return absl::InvalidArgumentError(
          fmt::format("invalid client init size (expected {}, got {})",
                      expectedClientInitSize, msg.client_init->size()));
      }

      auto clientMlkemPub = std::span{*msg.client_init}.first<MLKEM768_PUBLIC_KEY_BYTES>();
      auto clientX25519Pub = std::span{*msg.client_init}.subspan<MLKEM768_PUBLIC_KEY_BYTES, X25519_PUBLIC_VALUE_LEN>();
      MLKEM768_public_key clientMlkemPublicKey{};

      if (auto cbs = CBS{bssl::Span{clientMlkemPub}};
          !static_cast<bool>(MLKEM768_parse_public_key(&clientMlkemPublicKey, &cbs))) {
        return absl::InvalidArgumentError("invalid peer public key");
      }

      fixed_bytes<MLKEM768_CIPHERTEXT_BYTES + X25519_PUBLIC_VALUE_LEN> serverReply{};

      fixed_bytes<MLKEM_SHARED_SECRET_BYTES> mlkemSharedSecret{};
      MLKEM768_encap(std::span{serverReply}.first<MLKEM768_CIPHERTEXT_BYTES>().data(),
                     mlkemSharedSecret.data(),
                     &clientMlkemPublicKey);
      clientMlkemPublicKey = {};

      fixed_bytes<X25519_PRIVATE_KEY_LEN> serverX25519Priv{};
      X25519_keypair(std::span{serverReply}.subspan<MLKEM768_CIPHERTEXT_BYTES, X25519_PUBLIC_VALUE_LEN>().data(),
                     serverX25519Priv.data());

      openssh::Hash sharedSecretHash(hash_algorithm());
      sharedSecretHash.write(std::exchange(mlkemSharedSecret, {}));

      fixed_bytes<X25519_SHARED_KEY_LEN> x25519SharedSecret{};
      if (X25519(x25519SharedSecret.data(),
                 serverX25519Priv.data(),
                 clientX25519Pub.data()) == 0) {
        return absl::InvalidArgumentError("x25519 error");
      }
      serverX25519Priv.fill(0);
      sharedSecretHash.write(std::exchange(x25519SharedSecret, {}));

      auto blob = signer_->toPublicKeyBlob();
      auto res = computeServerResult(blob, *msg.client_init, std::exchange(serverReply, {}),
                                     sharedSecretHash.sum());
      if (!res.ok()) {
        return statusf("error computing server result: {}", res.status());
      }

      return *res;
    },
    [&msg](auto&) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    });
}

absl::StatusOr<std::optional<KexResultSharedPtr>> Mlkem768x25519KexAlgorithm::handleClientRecv(wire::Message& msg) {
  return msg.visit(
    [&](opt_ref<wire::KexHybridReplyMsg> opt_msg) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid key exchange reply");
      }
      auto& msg = opt_msg->get();
      const size_t expectedServerReplySize = MLKEM768_CIPHERTEXT_BYTES + X25519_PUBLIC_VALUE_LEN;
      if (msg.server_reply->size() != expectedServerReplySize) {
        return absl::InvalidArgumentError(
          fmt::format("invalid server reply size (expected {}, got {})",
                      expectedServerReplySize, msg.server_reply->size()));
      }
      auto ciphertext = std::span{*msg.server_reply}.first<MLKEM768_CIPHERTEXT_BYTES>();
      auto serverX25519Pub = std::span{*msg.server_reply}.subspan<MLKEM768_CIPHERTEXT_BYTES, X25519_PUBLIC_VALUE_LEN>();

      fixed_bytes<MLKEM_SHARED_SECRET_BYTES> mlkemSharedSecret{};
      static_assert(ciphertext.size() == MLKEM768_CIPHERTEXT_BYTES);
      auto r = MLKEM768_decap(mlkemSharedSecret.data(),
                              ciphertext.data(), ciphertext.size(),
                              &client_keypair_.mlkem768_priv);
      ASSERT(r == 1, "MLKEM768_decap failed"); // this only fails if ciphertext has the wrong size
      client_keypair_.mlkem768_priv = {};

      openssh::Hash sharedSecretHash(hash_algorithm());
      sharedSecretHash.write(std::exchange(mlkemSharedSecret, {}));

      fixed_bytes<X25519_SHARED_KEY_LEN> x25519SharedSecret{};
      if (!X25519(x25519SharedSecret.data(),
                  client_keypair_.curve25519_priv.data(),
                  serverX25519Pub.data())) {
        return absl::InvalidArgumentError("x25519 error");
      }
      client_keypair_.curve25519_priv.fill(0);

      sharedSecretHash.write(std::exchange(x25519SharedSecret, {}));

      auto res = computeClientResult(*msg.host_key, client_keypair_.pub, *msg.server_reply,
                                     sharedSecretHash.sum(), *msg.signature);
      if (!res.ok()) {
        return res.status();
      }
      return *res;
    },
    [&msg](auto&) -> absl::StatusOr<std::optional<KexResultSharedPtr>> {
      return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
    });
}

wire::Message Mlkem768x25519KexAlgorithm::buildClientInit() {
  MLKEM768_generate_key(std::span{client_keypair_.pub}.first<MLKEM768_PUBLIC_KEY_BYTES>().data(),
                        nullptr,
                        &client_keypair_.mlkem768_priv);
  X25519_keypair(std::span{client_keypair_.pub}.subspan<MLKEM768_PUBLIC_KEY_BYTES, X25519_PUBLIC_VALUE_LEN>().data(),
                 client_keypair_.curve25519_priv.data());

  return wire::KexHybridInitMsg{
    .client_init = to_bytes(client_keypair_.pub),
  };
}

const KexAlgorithm::MessageTypeList& Mlkem768x25519KexAlgorithm::clientInitMessageTypes() const {
  static MessageTypeList list{wire::KexHybridInitMsg::type};
  return list;
}

wire::Message Mlkem768x25519KexAlgorithm::buildServerReply(const KexResult& res) {
  return wire::KexHybridReplyMsg{
    .host_key = res.host_key_blob,
    .server_reply = res.server_ephemeral_pub_key,
    .signature = res.signature,
  };
}

const KexAlgorithm::MessageTypeList& Mlkem768x25519KexAlgorithm::serverReplyMessageTypes() const {
  static MessageTypeList list{wire::KexHybridReplyMsg::type};
  return list;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec