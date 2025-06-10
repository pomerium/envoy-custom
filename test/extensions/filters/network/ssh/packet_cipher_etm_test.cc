#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

struct CipherParameters {
  const char* const alg;
  size_t keySize;
};

class ETMPacketCipherTest : public testing::TestWithParam<std::tuple<CipherParameters, std::string>> {
public:
  void SetUp() override {
    auto [cipher, mac] = GetParam();
    DerivedKeys keys{
      .iv = randomBytes(16),
      .key = randomBytes(cipher.keySize),
      .mac = randomBytes(MACKeySizes.at(mac)),
    };
    DirectionAlgorithms algs{
      .cipher = cipher.alg,
      .mac = mac,
      .compression = "",
    };

    write_cipher_ = std::make_unique<ETMPacketCipher>(keys, algs, openssh::CipherMode::Write);
    read_cipher_ = std::make_unique<ETMPacketCipher>(keys, algs, openssh::CipherMode::Read);
  }

protected:
  std::unique_ptr<ETMPacketCipher> write_cipher_;
  std::unique_ptr<ETMPacketCipher> read_cipher_;
};

TEST_P(ETMPacketCipherTest, EncryptDecryptPacket) {
  wire::ChannelDataMsg msg;
  wire::test::populateFields(msg);

  Buffer::OwnedImpl buffer;
  ASSERT_OK(wire::encodePacket(buffer, msg, write_cipher_->blockSize(), write_cipher_->aadLen()).status());

  auto packetData = buffer.toString();

  Buffer::OwnedImpl encrypted;
  ASSERT_OK(write_cipher_->encryptPacket(0, encrypted, buffer));
  ASSERT_NE(packetData, encrypted.toString());

  Buffer::OwnedImpl decrypted;
  auto r = read_cipher_->decryptPacket(0, decrypted, encrypted);
  ASSERT_OK(r.status());
  ASSERT_EQ(packetData.size() - 4, *r);
  ASSERT_EQ(packetData, decrypted.toString());
}

TEST_P(ETMPacketCipherTest, DecryptPacketSmallerThanBlockSize) {
  // Attempting to decrypt an incomplete packet should not drain any buffer data.
  Buffer::OwnedImpl buffer("AA");

  Buffer::OwnedImpl decrypted;
  auto r = read_cipher_->decryptPacket(0, decrypted, buffer);
  ASSERT_OK(r.status());
  ASSERT_EQ(0, *r);
  ASSERT_EQ("AA", buffer.toString());
}

TEST_P(ETMPacketCipherTest, DecryptIncompletePacket) {
  // Generate an incomplete packet by dropping the last 4 bytes from a valid packet.
  wire::ChannelDataMsg msg;
  wire::test::populateFields(msg);

  Buffer::OwnedImpl buffer;
  ASSERT_OK(wire::encodePacket(buffer, msg, write_cipher_->blockSize(), write_cipher_->aadLen()).status());

  Buffer::OwnedImpl encrypted;
  ASSERT_OK(write_cipher_->encryptPacket(0, encrypted, buffer));

  Buffer::OwnedImpl incomplete;
  size_t length = encrypted.length() - 4;
  auto* data = encrypted.linearize(length);
  incomplete.add(data, length);

  // Attempting to decrypt an incomplete packet should not drain any buffer data.
  Buffer::OwnedImpl decrypted;
  auto r = read_cipher_->decryptPacket(0, decrypted, incomplete);
  ASSERT_OK(r.status());
  ASSERT_EQ(0, *r);
  ASSERT_EQ(length, incomplete.length());
}

TEST_P(ETMPacketCipherTest, DecryptBadCiphertext) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt(uint32_t(64));
  buffer.add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  buffer.add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

  Buffer::OwnedImpl decrypted;
  auto r = read_cipher_->decryptPacket(0, decrypted, buffer);
  ASSERT_FALSE(r.ok());
  ASSERT_EQ(absl::StatusCode::kInvalidArgument, r.status().code());
}

std::vector<CipherParameters> AllETMCipherParameters{
  {.alg = CipherAES128CTR,
   .keySize = 16},
  {.alg = CipherAES192CTR,
   .keySize = 24},
  {.alg = CipherAES256CTR,
   .keySize = 32},
};

INSTANTIATE_TEST_SUITE_P(ETMPacketCipherTestSuite, ETMPacketCipherTest,
                         testing::Combine(testing::ValuesIn(AllETMCipherParameters),
                                          testing::ValuesIn(SupportedMACs)));

TEST(ETMPacketCipherTest, NonETM) {
  DerivedKeys keys{
    .iv = bytes(16),
    .key = bytes(16),
    .mac = bytes(32),
  };
  DirectionAlgorithms algs{
    .cipher = "aes128-ctr",
    .mac = "hmac-sha2-256", // non-ETM MAC algorithm
    .compression = "",
  };
  EXPECT_THROW_WITH_MESSAGE(
    ETMPacketCipher(keys, algs, openssh::CipherMode::Read),
    EnvoyException,
    "unsupported mac algorithm (hmac-sha2-256): only etm mac algorithms are supported");
}

TEST(ETMPacketCipherFactoryTest, Factory) {
  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<AES128CTRCipherFactory>();
  factories.registerType<AES192CTRCipherFactory>();
  factories.registerType<AES256CTRCipherFactory>();

  auto expected = std::vector<std::string>{
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
  };
  EXPECT_EQ(expected, factories.namesByPriority());

  ASSERT_THAT(factories.factoryForName("aes128-ctr").get(),
              WhenDynamicCastTo<AES128CTRCipherFactory*>(NotNull()));

  ASSERT_THAT(factories.factoryForName("aes192-ctr").get(),
              WhenDynamicCastTo<AES192CTRCipherFactory*>(NotNull()));

  ASSERT_THAT(factories.factoryForName("aes256-ctr").get(),
              WhenDynamicCastTo<AES256CTRCipherFactory*>(NotNull()));

  for (auto params : AllETMCipherParameters) {
    auto factory = factories.factoryForName(params.alg);
    ASSERT_EQ(16, factory->ivSize()) << "unexpected IV size for " << params.alg;
    ASSERT_EQ(params.keySize, factory->keySize()) << "unexpected key size for " << params.alg;

    DerivedKeys keys{
      .iv = bytes(16),
      .key = bytes(params.keySize),
      .mac = bytes(32),
    };
    DirectionAlgorithms algs{
      .cipher = params.alg,
      .mac = "hmac-sha2-256-etm@openssh.com",
      .compression = "",
    };
    ASSERT_NE(nullptr, factory->create(keys, algs, openssh::CipherMode::Write));
  }
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
