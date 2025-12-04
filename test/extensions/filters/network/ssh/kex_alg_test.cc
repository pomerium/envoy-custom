#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

TEST(HandshakeMagicsTest, Encode) {
  HandshakeMagics magics;
  magics.client_version = to_bytes("SSH-2.0-Client"sv);
  magics.server_version = to_bytes("SSH-2.0-Server-Version"sv);
  // not testing the contents of the messages, just the encoding of HandshakeMagics
  magics.client_kex_init = to_bytes("client_kex_init_msg"sv);
  magics.server_kex_init = to_bytes("server_kex_init"sv);

  bytes expected = to_bytes("\x00\x00\x00\x0E"
                            "SSH-2.0-Client"
                            "\x00\x00\x00\x16"
                            "SSH-2.0-Server-Version"
                            "\x00\x00\x00\x13"
                            "client_kex_init_msg"
                            "\x00\x00\x00\x0F"
                            "server_kex_init"sv);
  Buffer::OwnedImpl actual;
  magics.encode(actual);
  ASSERT_EQ(expected, wire::flushTo<bytes>(actual));
}

bytes hexToBytes(std::string_view hex) {
  std::string out;
  EXPECT_TRUE(absl::HexStringToBytes(hex, &out));
  return to_bytes(out);
}

std::string hexToString(std::string_view hex) {
  std::string out;
  EXPECT_TRUE(absl::HexStringToBytes(hex, &out));
  return out;
}

class TestKexAlgorithm : public KexAlgorithm {
public:
  using KexAlgorithm::KexAlgorithm;
  ~TestKexAlgorithm() {}

  absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message&) override {
    return absl::UnimplementedError("unimplemented");
  }
  absl::StatusOr<std::optional<KexResultSharedPtr>> handleClientRecv(wire::Message&) override {
    return absl::UnimplementedError("unimplemented");
  }
  wire::Message buildClientInit() override {
    return {};
  }
  const MessageTypeList& clientInitMessageTypes() const override {
    static MessageTypeList list;
    return list;
  }
  wire::Message buildServerReply(const KexResult&) override {
    return {};
  }
  const MessageTypeList& serverReplyMessageTypes() const override {
    static MessageTypeList list;
    return list;
  }
  constexpr HashFunction hash_algorithm() const override { return SHA256; }
  constexpr SharedSecretEncoding shared_secret_encoding() const override { return shared_secret_encoding_; }

  using KexAlgorithm::computeClientResult;
  using KexAlgorithm::computeExchangeHash;
  using KexAlgorithm::computeServerResult;

  SharedSecretEncoding shared_secret_encoding_{};
};

/*
From https://datatracker.ietf.org/doc/html/rfc5656#section-4:

 The exchange hash H is computed as the hash of the concatenation of
   the following.

      string   V_C, client's identification string (CR and LF excluded)
      string   V_S, server's identification string (CR and LF excluded)
      string   I_C, payload of the client's SSH_MSG_KEXINIT
      string   I_S, payload of the server's SSH_MSG_KEXINIT
      string   K_S, server's public host key
      string   Q_C, client's ephemeral public key octet string
      string   Q_S, server's ephemeral public key octet string
      mpint    K,   shared secret
*/

class KexAlgorithmTestSuite : public testing::TestWithParam<SharedSecretEncoding> {
public:
  void SetUp() {
    client_version = to_bytes("SSH-2.0-Client"sv);
    server_version = to_bytes("SSH-2.0-Server-Version"sv);
    wire::KexInitMsg client_kex_init_msg;
    wire::test::populateFields(client_kex_init_msg);
    wire::KexInitMsg server_kex_init_msg;
    wire::test::populateFields(server_kex_init_msg);
    client_kex_init = *encodeTo<bytes>(client_kex_init_msg);
    server_kex_init = *encodeTo<bytes>(server_kex_init_msg);
    server_host_key = *openssh::SSHKey::generate(KEY_ED25519, 256);
    server_host_key_blob = server_host_key->toPublicKeyBlob();
    client_ephemeral_key = randomBytes(32);
    server_ephemeral_key = randomBytes(32);
    shared_secret = randomBytes(32);
  }

  void writeExchangeHashFields(Envoy::Buffer::Instance& dest) {
    wire::write_opt<wire::LengthPrefixed>(dest, client_version);
    wire::write_opt<wire::LengthPrefixed>(dest, server_version);
    wire::write_opt<wire::LengthPrefixed>(dest, client_kex_init);
    wire::write_opt<wire::LengthPrefixed>(dest, server_kex_init);
    wire::write_opt<wire::LengthPrefixed>(dest, server_host_key_blob);
    wire::write_opt<wire::LengthPrefixed>(dest, client_ephemeral_key);
    wire::write_opt<wire::LengthPrefixed>(dest, server_ephemeral_key);
    switch (GetParam()) {
    case SharedSecretEncoding::Bignum:
      wire::writeBignum(dest, shared_secret);
      break;
    case SharedSecretEncoding::String:
      wire::write_opt<wire::LengthPrefixed>(dest, shared_secret);
      break;
    }
  }

  bytes client_version;
  bytes server_version;
  bytes client_kex_init;
  bytes server_kex_init;
  openssh::SSHKeyPtr server_host_key;
  bytes server_host_key_blob;
  bytes client_ephemeral_key;
  bytes server_ephemeral_key;
  bytes shared_secret;
};

TEST_P(KexAlgorithmTestSuite, ComputeExchangeHash) {
  Buffer::OwnedImpl expected;
  writeExchangeHashFields(expected);
  openssh::Hash h("SHA256");
  h.write(wire::flushTo<bytes>(expected));
  auto expectedExchangeHash = h.sum();

  HandshakeMagics magics{client_version, server_version, client_kex_init, server_kex_init};
  Algorithms algs;

  algs.kex = "curve25519-sha256";
  auto kexAlg = TestKexAlgorithm(&magics, &algs, server_host_key.get());
  kexAlg.shared_secret_encoding_ = GetParam();
  auto actualExchangeHash = kexAlg.computeExchangeHash(server_host_key_blob,
                                                       client_ephemeral_key,
                                                       server_ephemeral_key,
                                                       shared_secret);
  EXPECT_EQ(actualExchangeHash, expectedExchangeHash);
}

TEST_P(KexAlgorithmTestSuite, ComputeServerResult) {
  HandshakeMagics magics{client_version, server_version, client_kex_init, server_kex_init};
  Algorithms algs;
  algs.kex = "curve25519-sha256";
  auto kexAlg = TestKexAlgorithm(&magics, &algs, server_host_key.get());
  kexAlg.shared_secret_encoding_ = GetParam();
  auto result = kexAlg.computeServerResult(server_host_key_blob,
                                           client_ephemeral_key,
                                           server_ephemeral_key,
                                           shared_secret);
  ASSERT_OK(result.status());
  auto& resPtr = *result;

  Buffer::OwnedImpl exchangeHashBuf;
  writeExchangeHashFields(exchangeHashBuf);
  openssh::Hash h(SHA256);
  h.write(wire::flushTo<bytes>(exchangeHashBuf));
  auto exchangeHash = h.sum();

  EXPECT_EQ(resPtr->exchange_hash, exchangeHash);
  EXPECT_EQ(resPtr->shared_secret, shared_secret);
  EXPECT_EQ(resPtr->shared_secret_encoding, GetParam());
  EXPECT_EQ(resPtr->host_key_blob, server_host_key_blob);
  EXPECT_EQ(resPtr->signature, *server_host_key->sign(exchangeHash));
  EXPECT_EQ(resPtr->hash, SHA256);
  EXPECT_TRUE(resPtr->session_id.empty());
  EXPECT_EQ(resPtr->server_ephemeral_pub_key, server_ephemeral_key);
  EXPECT_EQ(resPtr->algorithms, algs);
  EXPECT_FALSE(resPtr->client_supports_ext_info);
  EXPECT_FALSE(resPtr->server_supports_ext_info);
}

TEST_P(KexAlgorithmTestSuite, ComputeServerResult_SignError) {
  HandshakeMagics magics{client_version, server_version, client_kex_init, server_kex_init};
  Algorithms algs;
  algs.kex = "curve25519-sha256";
  auto badSigner = server_host_key->toPublicKey();
  auto kexAlg = TestKexAlgorithm(&magics, &algs, badSigner.get());
  kexAlg.shared_secret_encoding_ = GetParam();
  auto result = kexAlg.computeServerResult(server_host_key_blob,
                                           client_ephemeral_key,
                                           server_ephemeral_key,
                                           shared_secret);
  ASSERT_EQ(absl::InvalidArgumentError("error signing exchange hash: invalid argument"), result.status());
}

TEST_P(KexAlgorithmTestSuite, ComputeClientResult) {
  HandshakeMagics magics{client_version, server_version, client_kex_init, server_kex_init};
  Algorithms algs;
  algs.kex = "curve25519-sha256";
  auto kexAlg = TestKexAlgorithm(&magics, &algs, server_host_key.get());
  kexAlg.shared_secret_encoding_ = GetParam();

  Buffer::OwnedImpl exchangeHashBuf;
  writeExchangeHashFields(exchangeHashBuf);
  openssh::Hash h(SHA256);
  h.write(wire::flushTo<bytes>(exchangeHashBuf));
  auto exchangeHash = h.sum();
  auto signature = server_host_key->sign(exchangeHash);
  ASSERT_OK(signature.status());

  auto result = kexAlg.computeClientResult(server_host_key_blob,
                                           client_ephemeral_key,
                                           server_ephemeral_key,
                                           shared_secret,
                                           *signature);
  ASSERT_OK(result.status());
  auto& resPtr = *result;

  EXPECT_EQ(resPtr->exchange_hash, exchangeHash);
  EXPECT_EQ(resPtr->shared_secret, shared_secret);
  EXPECT_EQ(resPtr->shared_secret_encoding, GetParam());
  EXPECT_EQ(resPtr->host_key_blob, server_host_key_blob);
  EXPECT_EQ(resPtr->signature, *signature);
  EXPECT_EQ(resPtr->hash, SHA256);
  EXPECT_TRUE(resPtr->session_id.empty());
  EXPECT_EQ(resPtr->server_ephemeral_pub_key, server_ephemeral_key);
  EXPECT_EQ(resPtr->algorithms, algs);
  EXPECT_FALSE(resPtr->client_supports_ext_info);
  EXPECT_FALSE(resPtr->server_supports_ext_info);
}

TEST_P(KexAlgorithmTestSuite, ComputeClientResult_InvalidHostKeyBlob) {
  HandshakeMagics magics{client_version, server_version, client_kex_init, server_kex_init};
  Algorithms algs;
  algs.kex = "curve25519-sha256";
  auto kexAlg = TestKexAlgorithm(&magics, &algs, server_host_key.get());
  kexAlg.shared_secret_encoding_ = GetParam();
  server_host_key_blob[0] = ~server_host_key_blob[0];
  auto result = kexAlg.computeClientResult(server_host_key_blob,
                                           client_ephemeral_key,
                                           server_ephemeral_key,
                                           shared_secret,
                                           bytes{});
  ASSERT_EQ(absl::InvalidArgumentError("error reading host key blob: invalid format"), result.status());
}

TEST_P(KexAlgorithmTestSuite, ComputeClientResult_SignatureVerifyFailed) {
  HandshakeMagics magics{client_version, server_version, client_kex_init, server_kex_init};
  Algorithms algs;
  algs.kex = "curve25519-sha256";
  auto kexAlg = TestKexAlgorithm(&magics, &algs, server_host_key.get());
  kexAlg.shared_secret_encoding_ = GetParam();

  Buffer::OwnedImpl exchangeHashBuf;
  writeExchangeHashFields(exchangeHashBuf);
  openssh::Hash h(SHA256);
  h.write(wire::flushTo<bytes>(exchangeHashBuf));
  auto exchangeHash = h.sum();
  exchangeHash[0] = ~exchangeHash[0];
  auto signatureWithWrongPayload = server_host_key->sign(exchangeHash);

  auto result = kexAlg.computeClientResult(server_host_key_blob,
                                           client_ephemeral_key,
                                           server_ephemeral_key,
                                           shared_secret,
                                           *signatureWithWrongPayload);
  ASSERT_EQ(absl::PermissionDeniedError("signature failed verification: incorrect signature"), result.status());

  auto wrongKey = *openssh::SSHKey::generate(KEY_ED25519, 256);
  auto signatureWithWrongKey = wrongKey->sign(exchangeHash);
  result = kexAlg.computeClientResult(server_host_key_blob,
                                      client_ephemeral_key,
                                      server_ephemeral_key,
                                      shared_secret,
                                      *signatureWithWrongKey);
  ASSERT_EQ(absl::PermissionDeniedError("signature failed verification: incorrect signature"), result.status());
}

INSTANTIATE_TEST_SUITE_P(KexAlgorithmTest, KexAlgorithmTestSuite,
                         testing::Values(SharedSecretEncoding::Bignum, SharedSecretEncoding::String));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec