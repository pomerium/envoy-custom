#include "source/extensions/filters/network/ssh/wire/wire_test.h"

#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace wire::test {

// decodePacket

struct msgAllTypes : Msg<SshMessageType(200)> {
  field<bool> Bool;
  field<fixed_bytes<6>> Array;
  field<uint64_t> Uint64;
  field<uint32_t> Uint32;
  field<uint8_t> Uint8;
  field<std::string, LengthPrefixed> String;
  field<string_list, NameListFormat> Strings;
  field<bytes, LengthPrefixed> Bytes;
  field<bytes, LengthPrefixed> Bignum;

  bool operator==(const msgAllTypes& other) const = default;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept override {
    return decodeMsg(buffer, type, payload_size,
                     Bool, Array, Uint64, Uint32, Uint8, String, Strings, Bytes, Bignum);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept override {
    return encodeMsg(buffer, type,
                     Bool, Array, Uint64, Uint32, Uint8, String, Strings, Bytes, Bignum);
  }
};

namespace {
msgAllTypes newTestMsg1() {
  msgAllTypes test_msg;
  test_msg.Bool = true;
  test_msg.Array = fixed_bytes<6>{1, 2, 3, 4, 5, 6};
  test_msg.Uint64 = 0xDEADBEEFDEADBEEF;
  test_msg.Uint32 = 0xDEADBEEF;
  test_msg.Uint8 = 0xDE;
  test_msg.String = "asdf";
  test_msg.Strings = {"str1"s, "str2"s};
  test_msg.Bytes = bytes{0, 1, 2, 3, 4, 5};
  test_msg.Bignum = bytes{0x00, 0x00, 0x00, 0x02, 0x01, 0x02};
  return test_msg;
}

const auto testMsg1Expected = bytes{
  0x00, 0x00, 0x00, 0x44,                                              // message length
  0x05,                                                                // padding length
  0xC8,                                                                // message id (200)
  1,                                                                   // bool
  1, 2, 3, 4, 5, 6,                                                    // array
  0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,                      // uint64
  0xDE, 0xAD, 0xBE, 0xEF,                                              // uint32
  0xDE,                                                                // len || uint8
  0x00, 0x00, 0x00, 0x04, 'a', 's', 'd', 'f',                          // len || string
  0x00, 0x00, 0x00, 0x09, 's', 't', 'r', '1', ',', 's', 't', 'r', '2', // len || strings (comma separated)
  0x00, 0x00, 0x00, 0x06, 0, 1, 2, 3, 4, 5,                            // len || bytes
  0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02,          // len || bignum
  0x00, 0x00, 0x00, 0x00, 0x00                                         // padding (not random for test)
};
} // namespace

TEST(DecodePacketTest, Basic) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.add(testMsg1Expected.data(), testMsg1Expected.size());
  buffer.add(bytes{0, 0, 0, 0, 0}.data(), 5);

  msgAllTypes decoded;
  auto r = decodePacket(buffer, decoded);
  EXPECT_EQ(newTestMsg1(), decoded);
}

TEST(DecodePacketTest, ReadPacketLengthError) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeByte(1);
  buffer.writeByte(1);
  buffer.writeByte(1);
  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
  });
}

TEST(DecodePacketTest, ReadPaddingLengthError) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(123);
  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
  });
}

TEST(DecodePacketTest, DecodeError) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0x44);
  buffer.writeBEInt<uint8_t>(0x5);
  mock_err_encoder m;

  EXPECT_CALL(m, decode)
    .Times(1)
    .WillOnce(Return(absl::InternalError("test")));

  EXPECT_NO_THROW({
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
  });
}

TEST(DecodePacketTest, PacketPayloadSizeError) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0x44);
  buffer.writeBEInt<uint8_t>(0x5);
  mock_err_encoder m;

  EXPECT_CALL(m, decode)
    .Times(1)
    .WillOnce(Return(999)); // wrong size

  EXPECT_NO_THROW({
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
  });
}

TEST(DecodePacketTest, ReadPaddingError) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0x44);
  buffer.writeBEInt<uint8_t>(0x5);
  buffer.writeByte(0); //
  buffer.writeByte(0); // wrong padding length
  buffer.writeByte(0); //
  mock_err_encoder m;

  EXPECT_CALL(m, decode)
    .Times(1)
    .WillOnce(Return(0x44 - 0x5 - 1));

  EXPECT_NO_THROW({
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
  });
}

TEST(DecodePacketTest, InvalidPacket_PacketLengthTooLarge) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(MaxPacketSize + 1);
  buffer.writeBEInt<uint8_t>(4);

  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "invalid packet length");
  });
}

TEST(DecodePacketTest, InvalidPacket_PacketLengthTooSmall) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(MinPacketSize - 1);
  buffer.writeBEInt<uint8_t>(4);

  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "invalid packet length");
  });
}

TEST(DecodePacketTest, InvalidPacket_EmptyPayload) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(MinPacketSize);
  buffer.writeBEInt<uint8_t>(4);

  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "short read");
  });
}

TEST(DecodePacketTest, InvalidPacket_BufferUnderflow) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(MinPacketSize);

  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "error decoding packet: short read");
  });
}

TEST(DecodePacketTest, InvalidPacket_PaddingLengthTooLarge) {
  Envoy::Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(16);
  buffer.writeBEInt<uint8_t>(16);

  EXPECT_NO_THROW({
    msgAllTypes m;
    auto r = decodePacket(buffer, m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "invalid packet length");
  });
}

// encodePacket

TEST(EncodePacketTest, Basic) {
  Envoy::Buffer::OwnedImpl buffer;
  auto r = encodePacket(buffer, newTestMsg1(), 8, 0, false);
  EXPECT_TRUE(r.ok());

  EXPECT_EQ(testMsg1Expected, flushTo<bytes>(buffer));
}

TEST(EncodePacketTest, RandomPadding) {
  Envoy::Buffer::OwnedImpl buffer;
  auto r = encodePacket(buffer, newTestMsg1(), 8, 0, true);
  EXPECT_TRUE(r.ok());

  const auto encoded = flushTo<bytes>(buffer);
  auto expectedWithoutPadding = std::span{testMsg1Expected.data(), testMsg1Expected.size() - 5};
  auto actualWithoutPadding = std::span{encoded.data(), encoded.size() - 5};
  EXPECT_TRUE(std::equal(expectedWithoutPadding.begin(), expectedWithoutPadding.end(),
                         actualWithoutPadding.begin(), actualWithoutPadding.end()));

  auto zerosPadding = std::span{testMsg1Expected.data(), testMsg1Expected.size()}
                        .subspan(testMsg1Expected.size() - 5);
  auto actualPadding = std::span{encoded.data(), encoded.size()}
                         .subspan(encoded.size() - 5);
  EXPECT_FALSE(std::equal(zerosPadding.begin(), zerosPadding.end(),
                          actualPadding.begin(), actualPadding.end()));
}

class PaddingLengthTest
    : public testing::TestWithParam<std::tuple<uint32_t /*payload_length*/,
                                               uint32_t /*cipher_block_size*/,
                                               uint32_t /*expected*/>> {};
/*
RFC4253 § 6 (Binary Packet Protocol):
Each packet is in the following format:
uint32    packet_length
byte      padding_length
byte[n1]  payload; n1 = packet_length - padding_length - 1
byte[n2]  random padding; n2 = padding_length
---
Note that the length of the concatenation of 'packet_length',
'padding_length', 'payload', and 'random padding' MUST be a multiple
of the cipher block size or 8, whichever is larger.  This constraint
MUST be enforced, even when using stream ciphers.
*/

TEST_P(PaddingLengthTest, PaddingLength) {
  auto [payload_length, cipher_block_size, expected] = GetParam();
  auto actual = paddingLength(payload_length, cipher_block_size);
  EXPECT_EQ(expected, actual);
}

INSTANTIATE_TEST_SUITE_P(PaddingLengthTestSuite, PaddingLengthTest,
                         ::testing::Values(
                           std::tuple{10, 8, 9},            // (4+1+10)=15, next mult of 8 s.t. padlen >= 4 is 24
                           std::tuple{15, 16, 12},          // (4+1+15)=20, next mult of 16 s.t. padlen >= 4 is 32
                           std::tuple{0, 8, 11},            // (4+1+0)=5, next mult is 16
                           std::tuple{0, 4, 11},            // (4+1+0)=5, next mult is 16 (block size increased to 8)
                           std::tuple{20, 8, 7},            // (4+1+20)=25, next mult is 32
                           std::tuple{25, 16, 18},          // (4+1+25)=30, next mult is 48
                           std::tuple{50, 32, 9},           // (4+1+50)=55, next mult is 64
                           std::tuple{100, 64, 23},         // (4+1+100)=105, next mult is 128
                           std::tuple{1, 8, 10},            // (4+1+1)=6, next mult is 16
                           std::tuple{7, 8, 4},             // (4+1+7)=12, next mult is 16
                           std::tuple{8, 8, 11},            // (4+1+8)=13, next mult is 24
                           std::tuple{9, 8, 10},            // (4+1+9)=14, next mult is 24
                           std::tuple{31, 32, 28},          // (4+1+31)=36, next mult is 64
                           std::tuple{63, 64, 60},          // (4+1+63)=68, next mult is 128
                           std::tuple{127, 128, 124},       // (4+1+127)=132, next mult is 256
                           std::tuple{3, 4, 8},             // (4+1+3)=8, next mult is 16 (block size increased to 8)
                           std::tuple{3, 8, 8},             // (4+1+3)=8, next mult is 16
                           std::tuple{16 - 5, 16, 16},      // same as above, for block size=16
                           std::tuple{32 - 5, 32, 32},      // same as above, for block size=32
                           std::tuple{64 - 5, 64, 64},      // same as above, for block size=64
                           std::tuple{128 - 5, 128, 128})); // same as above, for block size=128

class PayloadLengthTest
    : public testing::TestWithParam<std::tuple<uint32_t /*packet_length*/,
                                               uint32_t /*padding_length*/,
                                               absl::StatusOr<uint32_t> /*expected*/>> {};

TEST_P(PayloadLengthTest, PayloadLength) {
  auto [packet_length, padding_length, expected] = GetParam();
  auto actual = payloadLength(packet_length, padding_length);
  EXPECT_EQ(expected, actual);
}

INSTANTIATE_TEST_SUITE_P(
  PayloadLengthTestSuite, PayloadLengthTest,
  ::testing::Values(
    std::tuple{0, 0, absl::InvalidArgumentError("invalid padding length")},
    std::tuple{0, 4, absl::InvalidArgumentError("invalid packet length")},
    std::tuple{16, 16, absl::InvalidArgumentError("invalid packet length")},
    std::tuple{MaxPacketSize + 1, 4, absl::InvalidArgumentError("invalid packet length")},
    std::tuple{MaxPacketSize - 3, 4, MaxPacketSize - 8},
    std::tuple{MaxPacketSize - 1, 4, MaxPacketSize - 6},
    std::tuple{16, 15, 0},
    std::tuple{17, 15, 1},
    std::tuple{1000, 255, 744}));

TEST(EncodePacketTest, Encode_EmptyPayloadError) {
  mock_err_encoder e;
  EXPECT_CALL(e, encode)
    .Times(1)
    .WillOnce(Return(0));

  Envoy::Buffer::OwnedImpl buffer;

  auto r = encodePacket(buffer, e);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::InvalidArgumentError("message encoded to 0 bytes"), r.status());
}

TEST(EncodePacketTest, Encode_PayloadTooLargeError) {
  mock_err_encoder e;
  EXPECT_CALL(e, encode)
    .Times(1)
    .WillOnce(Return(MaxPacketSize - 1));

  Envoy::Buffer::OwnedImpl buffer;
  auto r = encodePacket(buffer, e);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::InvalidArgumentError("encoded message is larger than the max packet size"), r.status());
}

TEST(EncodePacketTest, Encode_EncoderError) {
  mock_err_encoder e;
  EXPECT_CALL(e, encode)
    .Times(1)
    .WillOnce(Return(absl::InternalError("test")));

  Envoy::Buffer::OwnedImpl buffer;
  auto r = encodePacket(buffer, e);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::InternalError("test"), r.status());
}

} // namespace wire::test