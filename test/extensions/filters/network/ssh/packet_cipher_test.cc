#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class PacketCipherTest : public testing::Test {
public:
  void SetUp() {
    read_ = std::make_unique<testing::StrictMock<MockDirectionalPacketCipher>>();
    write_ = std::make_unique<testing::StrictMock<MockDirectionalPacketCipher>>();
  }

protected:
  std::unique_ptr<testing::StrictMock<MockDirectionalPacketCipher>> read_;
  std::unique_ptr<testing::StrictMock<MockDirectionalPacketCipher>> write_;
};

TEST_F(PacketCipherTest, EncryptPacket) {
  EXPECT_CALL(*write_, encryptPacket(0, _, _))
    .WillOnce(Return(0));

  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_OK(cipher.encryptPacket(0, buf, buf).status());
}

TEST_F(PacketCipherTest, DecryptPacket) {
  EXPECT_CALL(*read_, decryptPacket(0, _, _))
    .WillOnce(Return(0));

  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_OK(cipher.decryptPacket(0, buf, buf).status());
}

TEST_F(PacketCipherTest, BlockSizeRead) {
  EXPECT_CALL(*read_, blockSize())
    .WillOnce(Return(32));

  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(32, cipher.blockSize(openssh::CipherMode::Read));
}

TEST_F(PacketCipherTest, BlockSizeWrite) {
  EXPECT_CALL(*write_, blockSize())
    .WillOnce(Return(32));

  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(32, cipher.blockSize(openssh::CipherMode::Write));
}

TEST_F(PacketCipherTest, BlockSizeInvalid) {
  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_THROW_WITH_MESSAGE(cipher.blockSize(openssh::CipherMode(99)),
                            EnvoyException,
                            "unknown mode");
}

TEST_F(PacketCipherTest, AadSizeRead) {
  EXPECT_CALL(*read_, aadLen())
    .WillOnce(Return(32));

  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(32, cipher.aadSize(openssh::CipherMode::Read));
}

TEST_F(PacketCipherTest, AadSizeWrite) {
  EXPECT_CALL(*write_, aadLen())
    .WillOnce(Return(32));

  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(32, cipher.aadSize(openssh::CipherMode::Write));
}

TEST_F(PacketCipherTest, AadSizeInvalid) {
  PacketCipher cipher(std::move(read_), std::move(write_));
  Buffer::OwnedImpl buf;
  EXPECT_THROW_WITH_MESSAGE(cipher.aadSize(openssh::CipherMode(99)),
                            EnvoyException,
                            "unknown mode");
}

class RekeyAfterBytesTest : public PacketCipherTest,
                            public testing::WithParamInterface<std::tuple<openssh::CipherMode, std::tuple<size_t, std::optional<size_t>>>> {};

INSTANTIATE_TEST_SUITE_P(
  RekeyAfterBytesTestSuite, RekeyAfterBytesTest,
  testing::Combine(testing::Values(openssh::CipherMode::Read, openssh::CipherMode::Write),
                   testing::ValuesIn(std::vector<std::tuple<size_t, std::optional<size_t>>>{
                     {8uz, 1uz << 30},
                     {16uz, 16 * (1uz << ((16uz * 8) / 4))},
                     {32uz, std::nullopt},
                     {64uz, std::nullopt},
                     {4uz, std::nullopt},
                     {2uz, std::nullopt},
                     {0uz, std::nullopt},
                   })));

TEST_P(RekeyAfterBytesTest, RekeyAfterBytes_Read) {
  auto [mode, params] = GetParam();
  auto [block_size, expected] = params;

  EXPECT_CALL((mode == openssh::CipherMode::Read ? *read_ : *write_), blockSize())
    .WillOnce(Return(block_size));
  PacketCipher cipher(std::move(read_), std::move(write_));
  if (expected.has_value()) {
    EXPECT_EQ(expected.value(), cipher.rekeyAfterBytes(mode));
  } else {
    EXPECT_THROW_WITH_MESSAGE(cipher.rekeyAfterBytes(mode),
                              EnvoyException,
                              fmt::format("invalid block size: {}", block_size));
  }
}

TEST(NoCipherTest, EncryptDecryptPacket) {
  wire::KexInitMsg msg;
  wire::test::populateFields(msg);

  NoCipher no_cipher;
  Buffer::OwnedImpl buffer;
  ASSERT_OK(wire::encodePacket(buffer, msg, no_cipher.blockSize(), no_cipher.aadLen()).status());

  auto packetData = buffer.toString();

  Buffer::OwnedImpl encrypted; // not really encrypted
  auto r = no_cipher.encryptPacket(0, encrypted, buffer);
  ASSERT_OK(r.status());
  ASSERT_EQ(packetData.size(), *r);

  Buffer::OwnedImpl decrypted;
  r = no_cipher.decryptPacket(0, decrypted, encrypted);
  ASSERT_OK(r.status());
  ASSERT_EQ(packetData.size(), *r);
}

TEST(NoCipherTest, PacketTooLarge) {
  NoCipher no_cipher;
  Buffer::OwnedImpl buffer;
  // encodePacket won't encode an invalid packet size, but we can just write the length manually
  buffer.writeBEInt<uint32_t>(wire::MaxPacketSize + 1);

  Buffer::OwnedImpl out;
  auto r = no_cipher.decryptPacket(0, out, buffer);
  EXPECT_EQ(absl::InvalidArgumentError("invalid packet size"), r.status());
}

TEST(NoCipherTest, PacketTooSmall) {
  NoCipher no_cipher;
  Buffer::OwnedImpl buffer;
  ASSERT_TRUE(wire::MinPacketSize > 0); // sanity check
  buffer.writeBEInt<uint32_t>(wire::MinPacketSize - 1);

  Buffer::OwnedImpl out;
  auto r = no_cipher.decryptPacket(0, out, buffer);
  EXPECT_EQ(absl::InvalidArgumentError("invalid packet size"), r.status());
}

TEST(NoCipherTest, IncompletePacket) {
  NoCipher no_cipher;
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(50);

  Buffer::OwnedImpl out;
  auto r = no_cipher.decryptPacket(0, out, buffer);
  EXPECT_OK(r.status());
  EXPECT_EQ(0, *r);
}

TEST(NoCipherTest, Constants) {
  NoCipher no_cipher;
  EXPECT_EQ(8, no_cipher.blockSize());
  EXPECT_EQ(0, no_cipher.aadLen());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec