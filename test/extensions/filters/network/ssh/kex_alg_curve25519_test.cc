#include "source/extensions/filters/network/ssh/kex_alg_curve25519.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class KexAlgCurve25519TestSuite : public testing::Test {
public:
  void SetUp() {
    algs_.kex = "curve25519-sha256";
    algs_.host_key = "ssh-ed25519";
    magics_.client_version = to_bytes("SSH-2.0-Client"sv);
    magics_.server_version = to_bytes("SSH-2.0-Server-Version"sv);
    wire::KexInitMsg client_kex_init_msg;
    wire::test::populateFields(client_kex_init_msg);
    wire::KexInitMsg server_kex_init_msg;
    wire::test::populateFields(server_kex_init_msg);
    magics_.client_kex_init = *encodeTo<bytes>(client_kex_init_msg);
    magics_.server_kex_init = *encodeTo<bytes>(server_kex_init_msg);
    server_host_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);

    alg_ = factory_.create(&magics_, &algs_, server_host_key_.get());
  }

  std::unique_ptr<KexAlgorithm> alg_;

  Curve25519Sha256KexAlgorithmFactory factory_;

  // only used by base KexAlgorithm
  openssh::SSHKeyPtr server_host_key_;
  HandshakeMagics magics_;
  Algorithms algs_;
};

static absl::BitGen rng;

inline bytes randomBytes(size_t size) {
  bytes b;
  b.resize(size);
  for (size_t i = 0; i < b.size(); i++) {
    b[i] = absl::Uniform<uint8_t>(rng);
  }
  return b;
}

TEST_F(KexAlgCurve25519TestSuite, ClientInitMessageTypes) {
  EXPECT_EQ(KexAlgorithm::MessageTypeList{wire::SshMessageType::KexECDHInit}, alg_->clientInitMessageTypes());
}

TEST_F(KexAlgCurve25519TestSuite, ServerReplyMessageTypes) {
  EXPECT_EQ(KexAlgorithm::MessageTypeList{wire::SshMessageType::KexECDHReply}, alg_->serverReplyMessageTypes());
}

TEST_F(KexAlgCurve25519TestSuite, BuildClientInit) {
  auto init = alg_->buildClientInit();
  init.visit(
    [](opt_ref<wire::KexEcdhInitMsg> opt_msg) {
      ASSERT_TRUE(opt_msg.has_value());
      auto& msg = opt_msg.value().get();
      EXPECT_EQ(32, msg.client_pub_key->size());
    },
    [](auto&) {
      FAIL() << "invalid message type";
    });
}

TEST_F(KexAlgCurve25519TestSuite, BuildServerReply) {
  KexResult fake_result;
  fake_result.host_key_blob = randomBytes(32);
  fake_result.server_ephemeral_pub_key = randomBytes(32);
  fake_result.signature = randomBytes(32);
  auto msg = alg_->buildServerReply(fake_result);
  msg.visit(
    [&](opt_ref<wire::KexEcdhReplyMsg> opt_msg) {
      ASSERT_TRUE(opt_msg.has_value());
      auto& msg = opt_msg.value().get();
      EXPECT_EQ(msg.host_key, fake_result.host_key_blob);
      EXPECT_EQ(msg.ephemeral_pub_key, fake_result.server_ephemeral_pub_key);
      EXPECT_EQ(msg.signature, fake_result.signature);
    },
    [](auto&) {
      FAIL() << "invalid message type";
    });
}

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv) {
  auto init = alg_->buildClientInit();

  auto r = alg_->handleServerRecv(init);
  ASSERT_OK(r.status());
  ASSERT_TRUE(r->has_value());
  ASSERT_NE(nullptr, **r);
  auto& result = ***r;
  EXPECT_EQ(32, result.exchange_hash.size());
  EXPECT_EQ(32, result.shared_secret.size());
  EXPECT_OK((*openssh::SSHKey::fromPublicKeyBlob(result.host_key_blob))->verify(result.signature, result.exchange_hash));
  EXPECT_EQ(SHA256, result.hash);
  EXPECT_EQ(32, result.server_ephemeral_pub_key.size());
}

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv_WrongMessageType) {
  auto msg = wire::Message{wire::DebugMsg{}};
  auto r = alg_->handleServerRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("unexpected message received: Debug (4)"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv_WrongOverloadedMessageType) {
  Buffer::OwnedImpl buf;
  // write something with the same ID that won't decode correctly into KexEcdhInitMsg
  wire::write(buf, wire::SshMessageType::KexECDHInit);
  wire::write_opt<wire::LengthPrefixed>(buf, bytes{'f', 'o', 'o'});
  wire::write_opt<wire::LengthPrefixed>(buf, bytes{'b', 'a', 'r'});

  wire::Message msg;
  ASSERT_OK(msg.decode(buf, buf.length()).status());

  auto r = alg_->handleServerRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("invalid key exchange init"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv_WrongPublicKeySize) {
  wire::KexEcdhInitMsg init;
  init.client_pub_key->resize(31);
  auto msg = wire::Message{init};
  auto r = alg_->handleServerRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("invalid peer public key size (expected 32, got 31)"), r.status());
}

static constexpr fixed_bytes<32> curve25519_low_order_point{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
                                                            0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
                                                            0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
                                                            0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00};

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv_LowOrderInput) {
  wire::KexEcdhInitMsg init;
  init.client_pub_key = to_bytes(curve25519_low_order_point);
  auto msg = wire::Message{init};
  auto r = alg_->handleServerRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("x25519 error"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv_ZeroInput) {
  wire::KexEcdhInitMsg init;
  init.client_pub_key->resize(32);
  auto msg = wire::Message{init};
  auto r = alg_->handleServerRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("x25519 error"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleServerRecv_ComputeServerResultErr) {
  auto pubKey = server_host_key_->toPublicKey();
  auto algWithBadSigner = factory_.create(&magics_, &algs_, pubKey.get());
  auto init = algWithBadSigner->buildClientInit();
  auto r = algWithBadSigner->handleServerRecv(init);
  EXPECT_EQ(absl::InvalidArgumentError("error computing server result: error signing exchange hash: invalid argument"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv) {
  auto init = alg_->buildClientInit();
  auto r1 = alg_->handleServerRecv(init);
  ASSERT_OK(r1.status());
  ASSERT_TRUE(r1->has_value());
  auto reply = alg_->buildServerReply(***r1);
  auto r2 = alg_->handleClientRecv(reply);
  ASSERT_EQ(***r1, ***r2);
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_WrongMessageType) {
  auto msg = wire::Message{wire::DebugMsg{}};
  auto r = alg_->handleClientRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("unexpected message received: Debug (4)"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_WrongOverloadedMessageType) {
  Buffer::OwnedImpl buf;
  // write something with the same ID that won't decode correctly into KexEcdhReplyMsg
  wire::write(buf, wire::SshMessageType::KexECDHReply);
  wire::write_opt<wire::LengthPrefixed>(buf, bytes{'f', 'o', 'o'});
  wire::write_opt<wire::LengthPrefixed>(buf, bytes{'b', 'a', 'r'});

  wire::Message msg;
  ASSERT_OK(msg.decode(buf, buf.length()).status());

  auto r = alg_->handleClientRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("invalid key exchange reply"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_WrongPublicKeySize) {
  wire::KexEcdhReplyMsg reply;
  reply.ephemeral_pub_key->resize(31);
  auto msg = wire::Message{reply};
  auto r = alg_->handleClientRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("invalid peer public key size (expected 32, got 31)"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_LowOrderInput) {
  wire::KexEcdhReplyMsg reply;
  reply.ephemeral_pub_key = to_bytes(curve25519_low_order_point);
  auto msg = wire::Message{reply};
  auto r = alg_->handleClientRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("x25519 error"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_ZeroInput) {
  wire::KexEcdhReplyMsg reply;
  reply.ephemeral_pub_key->resize(32);
  auto msg = wire::Message{reply};
  auto r = alg_->handleClientRecv(msg);
  EXPECT_EQ(absl::InvalidArgumentError("x25519 error"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_ComputeClientResultError1) {
  auto init = alg_->buildClientInit();
  auto r1 = alg_->handleServerRecv(init);
  ASSERT_OK(r1.status());
  ASSERT_TRUE(r1->has_value());
  auto reply = alg_->buildServerReply(***r1);
  reply.visit(
    [](opt_ref<wire::KexEcdhReplyMsg> opt_msg) {
      auto& msg = opt_msg.value().get();
      msg.signature[0] = 0xFF; // modify the signature length
    },
    [](auto&) { FAIL() << "invalid message type"; });
  auto r = alg_->handleClientRecv(reply);
  EXPECT_EQ(absl::InvalidArgumentError("signature failed verification: string is too large"), r.status());
}

TEST_F(KexAlgCurve25519TestSuite, HandleClientRecv_ComputeClientResultError2) {
  auto init = alg_->buildClientInit();
  auto r1 = alg_->handleServerRecv(init);
  ASSERT_OK(r1.status());
  ASSERT_TRUE(r1->has_value());
  auto reply = alg_->buildServerReply(***r1);
  reply.visit(
    [](opt_ref<wire::KexEcdhReplyMsg> opt_msg) {
      auto& msg = opt_msg.value().get();
      msg.signature->back() = ~msg.signature->back(); // modify the signature payload
    },
    [](auto&) { FAIL() << "invalid message type"; });
  auto r = alg_->handleClientRecv(reply);
  EXPECT_EQ(absl::PermissionDeniedError("signature failed verification: incorrect signature"), r.status());
}

TEST(KexAlgCurve25519FactoryTest, Factory) {
  KexAlgorithmFactoryRegistry factories;
  factories.registerType<Curve25519Sha256KexAlgorithmFactory>();
  auto expected = std::vector<std::string>{"curve25519-sha256", "curve25519-sha256@libssh.org"};
  EXPECT_EQ(expected, factories.namesByPriority());

  ASSERT_THAT(factories.factoryForName("curve25519-sha256").get(),
              WhenDynamicCastTo<Curve25519Sha256KexAlgorithmFactory*>(NotNull()));

  ASSERT_THAT(factories.factoryForName("curve25519-sha256@libssh.org").get(),
              WhenDynamicCastTo<Curve25519Sha256KexAlgorithmFactory*>(NotNull()));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec