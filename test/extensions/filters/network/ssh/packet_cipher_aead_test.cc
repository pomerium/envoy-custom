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

class AEADPacketCipherTest : public testing::TestWithParam<CipherParameters> {};

TEST_P(AEADPacketCipherTest, EncryptDecryptPacket) {
  auto params = GetParam();
  DerivedKeys keys{
    .key = bytes(params.keySize),
    .iv = bytes(params.ivSize),
  };
  DirectionAlgorithms algs{ .cipher = params.alg };

  AEADPacketCipher writeCipher(keys, algs, openssh::CipherMode::Write);
  AEADPacketCipher readCipher(keys, algs, openssh::CipherMode::Write);

  wire::ChannelDataMsg msg;
  wire::test::populateFields(msg);

  Buffer::OwnedImpl buffer;
  ASSERT_OK(wire::encodePacket(buffer, msg, writeCipher.blockSize(), writeCipher.aadLen()).status());

  auto packetData = buffer.toString();

  Buffer::OwnedImpl encrypted;
  ASSERT_OK(writeCipher.encryptPacket(0, encrypted, buffer));
  ASSERT_NE(packetData, encrypted.toString());

  Buffer::OwnedImpl decrypted;
  auto r = readCipher.decryptPacket(0, decrypted, encrypted);
  ASSERT_OK(r.status());
  ASSERT_EQ(packetData.size() - 4, *r);
  ASSERT_EQ(packetData, decrypted.toString());
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