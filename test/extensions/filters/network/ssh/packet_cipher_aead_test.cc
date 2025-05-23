#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

struct CipherParameters {
  const char *const alg;
  size_t ivSize;
  size_t keySize;
};

class AEADPacketCipherTest : public testing::TestWithParam<CipherParameters> {
public:
  void SetUp() override {
    auto params = GetParam();
    DerivedKeys keys{
      .iv = bytes(params.ivSize),
      .key = bytes(params.keySize),
    };
    DirectionAlgorithms algs{ .cipher = params.alg };

    write_cipher_ = std::make_unique<AEADPacketCipher>(keys, algs, openssh::CipherMode::Write);
    read_cipher_ = std::make_unique<AEADPacketCipher>(keys, algs, openssh::CipherMode::Read);
  }

protected:
  std::unique_ptr<AEADPacketCipher> write_cipher_;
  std::unique_ptr<AEADPacketCipher> read_cipher_;
};

TEST_P(AEADPacketCipherTest, EncryptDecryptPacket) {
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

TEST_P(AEADPacketCipherTest, DecryptPacketSmallerThanBlockSize) {
  // Attempting to decrypt an incomplete packet should not drain any buffer data.
  Buffer::OwnedImpl buffer("AA");

  Buffer::OwnedImpl decrypted;
  auto r = read_cipher_->decryptPacket(0, decrypted, buffer);
  ASSERT_OK(r.status());
  ASSERT_EQ(0, *r);
  ASSERT_EQ("AA", buffer.toString());
}

TEST_P(AEADPacketCipherTest, DecryptIncompletePacket) {
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

INSTANTIATE_TEST_SUITE_P(AEADPacketCipherTestSuite, AEADPacketCipherTest,
  testing::ValuesIn(std::vector<CipherParameters>{
    { .alg = CipherChacha20Poly1305,
      .ivSize = 0,
      .keySize = 64 },
    { .alg = CipherAES128GCM,
      .ivSize = 12,
      .keySize = 16 },
    { .alg = CipherAES256GCM,
      .ivSize = 12,
      .keySize = 32 },
  }));

}
}