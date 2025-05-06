#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>

#include "source/common/factory.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/kex.h"
#include "openssh/digest.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct HandshakeMagics {
  std::string client_version;
  std::string server_version;
  bytes client_kex_init;
  bytes server_kex_init;

  void encode(Envoy::Buffer::Instance& buffer) const {
    wire::write_opt<wire::LengthPrefixed>(buffer, client_version);
    wire::write_opt<wire::LengthPrefixed>(buffer, server_version);
    wire::write_opt<wire::LengthPrefixed>(buffer, client_kex_init);
    wire::write_opt<wire::LengthPrefixed>(buffer, server_kex_init);
  }
};

enum HashFunction : int {
  SHA256 = SSH_DIGEST_SHA256,
  SHA512 = SSH_DIGEST_SHA512,
};

struct KexResult {
  bytes exchange_hash; // 'H'
  bytes shared_secret; // 'K'; not encoded as a length-prefixed bignum
  bytes host_key_blob;
  bytes signature;
  HashFunction hash;
  bytes session_id;
  bytes server_ephemeral_pub_key;
  Algorithms algorithms;
  bool client_supports_ext_info;
  bool server_supports_ext_info;

  auto operator<=>(const KexResult&) const = default;

  void encodeSharedSecret(bytes& out) {
    Envoy::Buffer::OwnedImpl tmp;
    wire::writeBignum(tmp, shared_secret);
    wire::flushTo<bytes>(tmp, out);
  }
};
using KexResultSharedPtr = std::shared_ptr<KexResult>;

class KexAlgorithm : public Logger::Loggable<Logger::Id::filter> {
  friend class Kex;

public:
  KexAlgorithm(const HandshakeMagics* magics, const Algorithms* algs,
               const openssh::SSHKey* signer);
  virtual ~KexAlgorithm() = default;

  using MessageTypeList = absl::flat_hash_set<wire::SshMessageType>;
  virtual absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message& msg) PURE;
  virtual absl::StatusOr<std::optional<KexResultSharedPtr>> handleClientRecv(wire::Message& msg) PURE;
  virtual wire::Message buildClientInit() PURE;
  virtual const MessageTypeList& clientInitMessageTypes() const PURE;
  virtual wire::Message buildServerReply(const KexResult&) PURE;
  virtual const MessageTypeList& serverReplyMessageTypes() const PURE;

protected:
  const HandshakeMagics* magics_;
  const Algorithms* algs_;
  const openssh::SSHKey* signer_;

  bytes computeExchangeHash(wire::Writer auto const& host_key_blob,
                            wire::Writer auto const& client_pub_key,
                            wire::Writer auto const& server_pub_key,
                            wire::Writer auto const& shared_secret) {
    Envoy::Buffer::OwnedImpl exchangeHash;
    magics_->encode(exchangeHash);
    wire::write_opt<wire::LengthPrefixed>(exchangeHash, host_key_blob);
    wire::write_opt<wire::LengthPrefixed>(exchangeHash, client_pub_key);
    wire::write_opt<wire::LengthPrefixed>(exchangeHash, server_pub_key);
    wire::writeBignum(exchangeHash, shared_secret);

    fixed_bytes<SSH_DIGEST_MAX_LENGTH> digestBuf;
    auto exchangeHashBuf = linearizeToSpan(exchangeHash);
    auto hash_alg = kex_hash_from_name(algs_->kex.c_str());
    ssh_digest_memory(hash_alg, exchangeHashBuf.data(), exchangeHashBuf.size(), digestBuf.data(), digestBuf.size());
    exchangeHash.drain(exchangeHash.length());
    return to_bytes(bytes_view{digestBuf}.first(ssh_digest_bytes(hash_alg)));
  }

  absl::StatusOr<KexResultSharedPtr> computeServerResult(wire::Writer auto const& host_key_blob,
                                                         wire::Writer auto const& client_pub_key,
                                                         wire::Writer auto const& server_pub_key,
                                                         wire::Writer auto const& shared_secret) {

    auto result = std::make_shared<KexResult>();
    result->algorithms = *algs_;
    result->host_key_blob = host_key_blob;

    auto digest = computeExchangeHash(host_key_blob, client_pub_key, server_pub_key, shared_secret);
    auto sig = signer_->sign(digest);
    if (!sig.ok()) {
      return statusf("error signing exchange hash: {}", sig.status());
    }

    result->exchange_hash = to_bytes(digest);
    result->shared_secret = to_bytes(shared_secret);
    result->signature = *sig;
    result->hash = SHA256;
    result->server_ephemeral_pub_key = to_bytes(server_pub_key);
    // session id is not set here

    return result;
  }

  absl::StatusOr<KexResultSharedPtr> computeClientResult(wire::Writer auto const& host_key_blob,
                                                         wire::Writer auto const& client_pub_key,
                                                         wire::Writer auto const& server_pub_key,
                                                         wire::Writer auto const& shared_secret,
                                                         const bytes& signature) {

    auto result = std::make_shared<KexResult>();
    result->algorithms = *algs_;
    result->host_key_blob = host_key_blob;

    auto digest = computeExchangeHash(host_key_blob, client_pub_key, server_pub_key, shared_secret);

    auto server_host_pubkey = openssh::SSHKey::fromPublicKeyBlob(host_key_blob);
    if (!server_host_pubkey.ok()) {
      return statusf("error reading host key blob: {}", server_host_pubkey.status());
    }

    auto stat = (*server_host_pubkey)->verify(signature, digest);
    if (!stat.ok()) {
      return statusf("signature failed verification: {}", stat);
    }

    result->exchange_hash = to_bytes(digest);
    result->shared_secret = to_bytes(shared_secret);
    result->signature = signature;
    result->hash = SHA256;
    result->server_ephemeral_pub_key = to_bytes(server_pub_key);
    // session id is not set here

    return result;
  }
};

class KexAlgorithmFactory {
public:
  virtual ~KexAlgorithmFactory() = default;
  virtual std::vector<std::pair<std::string, priority_t>> names() const PURE;
  virtual std::unique_ptr<KexAlgorithm> create(const HandshakeMagics* magics, const Algorithms* algs,
                                               const openssh::SSHKey* signer) const PURE;
};

using KexAlgorithmFactoryRegistry = PriorityAwareFactoryRegistry<KexAlgorithmFactory,
                                                                 KexAlgorithm,
                                                                 const HandshakeMagics*,
                                                                 const Algorithms*,
                                                                 const openssh::SSHKey*>;
using KexAlgorithmFactoryPtr = std::unique_ptr<KexAlgorithmFactory>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec