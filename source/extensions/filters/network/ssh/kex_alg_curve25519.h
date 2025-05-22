#pragma once

#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "openssl/curve25519.h"
namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr auto kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org";
static constexpr auto kexAlgoCurve25519SHA256 = "curve25519-sha256";

struct Curve25519Keypair {
  fixed_bytes<X25519_PRIVATE_KEY_LEN> priv;
  fixed_bytes<X25519_PUBLIC_VALUE_LEN> pub;
};

// Implements https://datatracker.ietf.org/doc/html/rfc8731
class Curve25519Sha256KexAlgorithm : public KexAlgorithm {
public:
  using KexAlgorithm::KexAlgorithm;

  absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message& msg) override;
  absl::StatusOr<std::optional<KexResultSharedPtr>> handleClientRecv(wire::Message& msg) override;
  wire::Message buildClientInit() override;
  const MessageTypeList& clientInitMessageTypes() const override;
  wire::Message buildServerReply(const KexResult&) override;
  const MessageTypeList& serverReplyMessageTypes() const override;
  constexpr HashFunction hash_algorithm() const override { return SHA256; }

private:
  Curve25519Keypair client_keypair_;
};

class Curve25519Sha256KexAlgorithmFactory : public KexAlgorithmFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{kexAlgoCurve25519SHA256, 0},
            {kexAlgoCurve25519SHA256LibSSH, 0}};
  }

  std::unique_ptr<KexAlgorithm> create(
    const HandshakeMagics* magics,
    const Algorithms* algs,
    const openssh::SSHKey* signer) const override {
    return std::make_unique<Curve25519Sha256KexAlgorithm>(magics, algs, signer);
  }
};
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec