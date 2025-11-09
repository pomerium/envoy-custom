#pragma once

#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "openssl/curve25519.h"

#include "openssl/mlkem.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr auto kexAlgoMlkem768x25519 = "mlkem768x25519-sha256";

struct HybridMlkem768Curve25519Keypair {
  MLKEM768_private_key mlkem768_priv;
  fixed_bytes<X25519_PRIVATE_KEY_LEN> curve25519_priv;
  fixed_bytes<MLKEM768_PUBLIC_KEY_BYTES + X25519_PUBLIC_VALUE_LEN> pub;
};

// Implements https://datatracker.ietf.org/doc/html/draft-ietf-sshm-mlkem-hybrid-kex-03
class Mlkem768x25519KexAlgorithm : public KexAlgorithm {
public:
  using KexAlgorithm::KexAlgorithm;

  absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message& msg) override;
  absl::StatusOr<std::optional<KexResultSharedPtr>> handleClientRecv(wire::Message& msg) override;
  wire::Message buildClientInit() override;
  const MessageTypeList& clientInitMessageTypes() const override;
  wire::Message buildServerReply(const KexResult& res) override;
  const MessageTypeList& serverReplyMessageTypes() const override;

  constexpr HashFunction hash_algorithm() const override { return SHA256; }
  constexpr SharedSecretEncoding shared_secret_encoding() const override { return SharedSecretEncoding::String; }

private:
  HybridMlkem768Curve25519Keypair client_keypair_{};
};

class Mlkem768x25519KexAlgorithmFactory : public KexAlgorithmFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{kexAlgoMlkem768x25519, 0}};
  }

  std::unique_ptr<KexAlgorithm> create(
    const HandshakeMagics* magics,
    const Algorithms* algs,
    const openssh::SSHKey* signer) const override {
    return std::make_unique<Mlkem768x25519KexAlgorithm>(magics, algs, signer);
  }
};
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec