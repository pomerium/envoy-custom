#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/field.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace wire {

using testing::Return;

// some test constants from openssh
static const bytes bn1 = {0x00, 0x00, 0x00};
static const bytes bn2 = {0x00, 0x00, 0x01, 0x02};
static const bytes bn3 = {0x00, 0x80, 0x09};
static const bytes bn_exp1 = {0x00, 0x00, 0x00, 0x00};
static const bytes bn_exp2 = {0x00, 0x00, 0x00, 0x02, 0x01, 0x02};
static const bytes bn_exp3 = {0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x09};

TEST(WriteBignumTest, EmptyBuf) {
  Envoy::Buffer::OwnedImpl buffer;
  EXPECT_EQ(4, writeBignum(buffer, {}));
  EXPECT_EQ(4, buffer.length());
}

TEST(WriteBignumTest, AllZeros) {
  Envoy::Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp1.size(), writeBignum(buffer, bn1));
  EXPECT_EQ(bn_exp1, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, Simple) {
  Envoy::Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp2.size(), writeBignum(buffer, std::span{bn2}.subspan(2)));
  EXPECT_EQ(bn_exp2, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, LeadingZero) {
  Envoy::Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp2.size(), writeBignum(buffer, bn2));
  EXPECT_EQ(bn_exp2, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, Negative) {
  Envoy::Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp3.size(), writeBignum(buffer, std::span{bn3}.subspan(1)));
  EXPECT_EQ(bn_exp3, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, NegativeAndLeadingZero) {
  Envoy::Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp3.size(), writeBignum(buffer, bn3));
  EXPECT_EQ(bn_exp3, flushTo<bytes>(buffer));
}

TEST(FlushToTest, String) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.add("testing");
    EXPECT_EQ("testing", flushTo<std::string>(buffer));
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    std::string out;
    buffer.add("testing");
    flushTo(buffer, out);
    EXPECT_EQ("testing", out);
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    EXPECT_EQ("", flushTo<std::string>(buffer));
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    std::string out;
    flushTo<std::string>(buffer, out);
    EXPECT_EQ("", out);
  }
}

TEST(FlushToTest, Bytes) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    auto b = to_bytes(std::string_view("testing"));
    buffer.add(b.data(), b.size());
    EXPECT_EQ(b, flushTo<bytes>(buffer));
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    auto expected = to_bytes(std::string_view("testing"));
    buffer.add(expected.data(), expected.size());
    bytes out;
    flushTo<bytes>(buffer, out);
    EXPECT_EQ(expected, out);
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    EXPECT_EQ(bytes{}, flushTo<bytes>(buffer));
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    bytes out;
    flushTo<bytes>(buffer, out);
    EXPECT_EQ(bytes{}, out);
  }
}

TEST(EncodeToTest, String) {
  {
    field<std::string> f{};
    f.value = "testing";
    auto r = encodeTo<std::string>(f);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ("testing", *r);
  }
  {
    field<std::string> f{};
    f.value = "testing";
    std::string out;
    auto r = encodeTo<std::string>(f, out);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(7, *r);
  }
  {
    field<std::string> f{};
    auto r = encodeTo<std::string>(f);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ("", *r);
  }
  {
    field<std::string> f{};
    std::string out;
    auto r = encodeTo<std::string>(f, out);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(0, *r);
  }
}

TEST(EncodeToTest, Bytes) {
  {
    field<bytes> f{};
    auto b = to_bytes(std::string_view("testing"));
    f.value = b;
    auto r = encodeTo<bytes>(f);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(b, *r);
  }
  {
    field<bytes> f{};
    auto b = to_bytes(std::string_view("testing"));
    f.value = b;
    bytes out;
    auto r = encodeTo<bytes>(f, out);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(7, *r);
  }
  {
    field<bytes> f{};
    auto r = encodeTo<bytes>(f);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(bytes{}, *r);
  }
  {
    field<bytes> f{};
    bytes out;
    auto r = encodeTo<bytes>(f, out);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(0, *r);
    EXPECT_EQ(bytes{}, out);
  }
}

template <typename T>
struct mock_encoder {
  MOCK_METHOD(absl::StatusOr<size_t>, decode, (Envoy::Buffer::Instance&, size_t), (noexcept));
  MOCK_METHOD(absl::StatusOr<size_t>, encode, (Envoy::Buffer::Instance&), (noexcept));
};

TEST(EncodeToTest, String_ErrorHandling) {
  {
    mock_encoder<std::string> m;

    EXPECT_CALL(m, encode)
        .Times(1)
        .WillOnce(Return(absl::InternalError("test")));

    auto r = encodeTo<std::string>(m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("test", r.status().message());
  }
  {
    mock_encoder<std::string> m;

    EXPECT_CALL(m, encode)
        .Times(1)
        .WillOnce(Return(absl::InternalError("test")));

    std::string out;
    auto r = encodeTo<std::string>(m, out);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("test", r.status().message());
  }
}
TEST(EncodeToTest, Bytes_ErrorHandling) {
  {
    mock_encoder<bytes> m;

    EXPECT_CALL(m, encode)
        .Times(1)
        .WillOnce(Return(absl::InternalError("test")));

    auto r = encodeTo<bytes>(m);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("test", r.status().message());
  }
  {
    mock_encoder<bytes> m;

    EXPECT_CALL(m, encode)
        .Times(1)
        .WillOnce(Return(absl::InternalError("test")));

    bytes out;
    auto r = encodeTo<bytes>(m, out);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("test", r.status().message());
  }
}

TEST(ReadIntTest, Uint8) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint8_t>(123);

    EXPECT_NO_THROW({
      uint8_t out{};
      auto n = read(buffer, out, sizeof(out));
      EXPECT_EQ(1, n);
      EXPECT_EQ(123, out);
      EXPECT_EQ(buffer.length(), 0);
    });
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    uint8_t out{};
    EXPECT_THROW({ read(buffer, out, sizeof(out)); }, Envoy::EnvoyException);
  }
}

TEST(ReadIntTest, Uint32) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint32_t>(12345);

    EXPECT_NO_THROW({
      uint32_t out{};
      auto n = read(buffer, out, sizeof(out));
      EXPECT_EQ(4, n);
      EXPECT_EQ(12345, out);
      EXPECT_EQ(buffer.length(), 0);
    });
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeByte(1);
    buffer.writeByte(2);
    buffer.writeByte(3);

    uint32_t out{};
    EXPECT_THROW({ read(buffer, out, sizeof(out)); }, Envoy::EnvoyException);
  }
}

TEST(ReadIntTest, SshMessageType) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeBEInt(static_cast<SshMessageType>(50));

    EXPECT_NO_THROW({
      SshMessageType out{};
      auto n = read(buffer, out, sizeof(out));
      EXPECT_EQ(1, n);
      EXPECT_EQ(SshMessageType(50), out);
      EXPECT_EQ(buffer.length(), 0);
    });
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    SshMessageType out{};
    EXPECT_THROW({ read(buffer, out, sizeof(out)); }, Envoy::EnvoyException);
  }
}

TEST(ReadIntTest, Bool) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint8_t>(1);

    EXPECT_NO_THROW({
      bool out{};
      auto n = read(buffer, out, sizeof(out));
      EXPECT_EQ(1, n);
      EXPECT_EQ(true, out);
      EXPECT_EQ(buffer.length(), 0);
    });
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint8_t>(0);

    EXPECT_NO_THROW({
      bool out{};
      auto n = read(buffer, out, sizeof(out));
      EXPECT_EQ(1, n);
      EXPECT_EQ(false, out);
      EXPECT_EQ(buffer.length(), 0);
    });
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint8_t>(10);

    EXPECT_NO_THROW({
      bool out{};
      auto n = read(buffer, out, sizeof(out));
      EXPECT_EQ(1, n);
      EXPECT_EQ(true, out);
      EXPECT_EQ(buffer.length(), 0);
    });
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    bool out{};
    EXPECT_THROW({ read(buffer, out, sizeof(out)); }, Envoy::EnvoyException);
  }
}

TEST(WriteIntTest, Uint8) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint8_t>(123));

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(123, buffer.peekBEInt<uint8_t>());
  }
}

TEST(WriteIntTest, Uint32) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint32_t>(12345));

    EXPECT_EQ(4, buffer.length());
    EXPECT_EQ(12345, buffer.peekBEInt<uint32_t>());
  }
}

TEST(WriteIntTest, SshMessageType) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    write(buffer, static_cast<SshMessageType>(50));

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(SshMessageType(50), buffer.peekBEInt<SshMessageType>());
  }
}

TEST(WriteIntTest, Bool) {
  {
    Envoy::Buffer::OwnedImpl buffer;
    write(buffer, true);

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(1, buffer.peekBEInt<uint8_t>());
  }
  {
    Envoy::Buffer::OwnedImpl buffer;
    write(buffer, false);

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(0, buffer.peekBEInt<uint8_t>());
  }
}

} // namespace wire