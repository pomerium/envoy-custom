#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "test/test_common/test_common.h"
#include "test/extensions/filters/network/ssh/wire/test_mocks.h"

#include "openssl/rand.h"

namespace wire::test {

// some test bignum values from openssh
static const bytes bn1 = {0x00, 0x00, 0x00};
static const bytes bn2 = {0x00, 0x00, 0x01, 0x02};
static const bytes bn3 = {0x00, 0x80, 0x09};
static const bytes bn_exp1 = {0x00, 0x00, 0x00, 0x00};
static const bytes bn_exp2 = {0x00, 0x00, 0x00, 0x02, 0x01, 0x02};
static const bytes bn_exp3 = {0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x09};

TEST(WriteBignumTest, EmptyBuf) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(4, writeBignum(buffer, {}));
  EXPECT_EQ(4, buffer.length());
  EXPECT_EQ(0, buffer.peekBEInt<uint32_t>());
}

TEST(WriteBignumTest, AllZeros) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp1.size(), writeBignum(buffer, bn1));
  EXPECT_EQ(bn_exp1, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, Simple) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp2.size(), writeBignum(buffer, std::span{bn2}.subspan(2)));
  EXPECT_EQ(bn_exp2, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, LeadingZero) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp2.size(), writeBignum(buffer, bn2));
  EXPECT_EQ(bn_exp2, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, Negative) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp3.size(), writeBignum(buffer, std::span{bn3}.subspan(1)));
  EXPECT_EQ(bn_exp3, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, NegativeAndLeadingZero) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(bn_exp3.size(), writeBignum(buffer, bn3));
  EXPECT_EQ(bn_exp3, flushTo<bytes>(buffer));
}

TEST(WriteBignumTest, InputTooLarge) {
  Buffer::OwnedImpl buffer;
  bytes b(2049, 1);
  EXPECT_THROW_WITH_MESSAGE(
    writeBignum(buffer, b),
    Envoy::EnvoyException,
    "input too large");
}

TEST(FlushToTest, String) {
  {
    Buffer::OwnedImpl buffer;
    buffer.add("testing");
    EXPECT_EQ("testing", flushTo<std::string>(buffer));
  }
  {
    Buffer::OwnedImpl buffer;
    std::string out;
    buffer.add("testing");
    flushTo(buffer, out);
    EXPECT_EQ("testing", out);
  }
  {
    Buffer::OwnedImpl buffer;
    EXPECT_EQ("", flushTo<std::string>(buffer));
  }
  {
    Buffer::OwnedImpl buffer;
    std::string out;
    flushTo<std::string>(buffer, out);
    EXPECT_EQ("", out);
  }
}

TEST(FlushToTest, Bytes) {
  {
    Buffer::OwnedImpl buffer;
    auto b = to_bytes(std::string_view("testing"));
    buffer.add(b.data(), b.size());
    EXPECT_EQ(b, flushTo<bytes>(buffer));
  }
  {
    Buffer::OwnedImpl buffer;
    auto expected = to_bytes(std::string_view("testing"));
    buffer.add(expected.data(), expected.size());
    bytes out;
    flushTo<bytes>(buffer, out);
    EXPECT_EQ(expected, out);
  }
  {
    Buffer::OwnedImpl buffer;
    EXPECT_EQ(bytes{}, flushTo<bytes>(buffer));
  }
  {
    Buffer::OwnedImpl buffer;
    bytes out;
    flushTo<bytes>(buffer, out);
    EXPECT_EQ(bytes{}, out);
  }
}

using testStringTypes = Types<std::string, bytes>;

static std::tuple<std::vector<std::string>, std::vector<bytes>> allParams{
  {
    // Test cases for std::string
    {"testing"},
    {""},
    {'\0'},
  },
  {
    // Test cases for bytes
    {'t', 'e', 's', 't', 'i', 'n', 'g'},
    {},
    {'\0'},
  },
};

template <SshStringType T>
class EncodeToTest : public testing::Test {
public:
  EncodeToTest()
      : params{std::get<std::vector<T>>(allParams)} {}
  MockEncoder encoder;
  std::vector<T> params;
};

TYPED_TEST_SUITE(EncodeToTest, testStringTypes);

TYPED_TEST(EncodeToTest, EncodeTo1) {
  for (const auto& input : this->params) {
    EXPECT_CALL(this->encoder, encode(_)).WillOnce(Invoke([&](Buffer::Instance& buf) {
      return write(buf, input);
    }));
    auto r = encodeTo<TypeParam>(this->encoder);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(input, *r);
  }
}

TYPED_TEST(EncodeToTest, EncodeTo2) {
  for (const auto& input : this->params) {
    EXPECT_CALL(this->encoder, encode(_)).WillOnce(Invoke([&](Buffer::Instance& buf) {
      return write(buf, input);
    }));
    TypeParam out;
    auto r = encodeTo<TypeParam>(this->encoder, out);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(input, out);
    EXPECT_EQ(input.size(), *r);
  }
}

TYPED_TEST(EncodeToTest, ErrorHandling) {
  EXPECT_CALL(this->encoder, encode(_)).WillRepeatedly(Return(absl::InternalError("test")));
  {
    auto r = encodeTo<TypeParam>(this->encoder);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("test", r.status().message());
  }
  {
    TypeParam out;
    auto r = encodeTo<TypeParam>(this->encoder, out);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("test", r.status().message());
  }
}

TEST(ReadIntTest, Uint8) {
  {
    Buffer::OwnedImpl buffer;
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
    Buffer::OwnedImpl buffer;
    uint8_t out{};
    EXPECT_SHORT_READ(read(buffer, out, sizeof(out)));
  }
}

TEST(ReadIntTest, Uint32) {
  {
    Buffer::OwnedImpl buffer;
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
    Buffer::OwnedImpl buffer;
    buffer.writeByte(1);
    buffer.writeByte(2);
    buffer.writeByte(3);

    uint32_t out{};
    EXPECT_THROW_WITH_MESSAGE(
      read(buffer, out, sizeof(out)),
      EnvoyException,
      "short read");
  }
}

TEST(ReadIntTest, SshMessageType) {
  {
    Buffer::OwnedImpl buffer;
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
    Buffer::OwnedImpl buffer;
    SshMessageType out{};
    EXPECT_THROW_WITH_MESSAGE(
      read(buffer, out, sizeof(out)),
      EnvoyException,
      "short read");
  }
}

TEST(ReadIntTest, Bool) {
  {
    Buffer::OwnedImpl buffer;
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
    Buffer::OwnedImpl buffer;
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
    Buffer::OwnedImpl buffer;
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
    Buffer::OwnedImpl buffer;
    bool out{};
    EXPECT_SHORT_READ(read(buffer, out, sizeof(out)));
  }
  {
    Buffer::OwnedImpl buffer;
    bool out{};
    EXPECT_SHORT_READ(read(buffer, out, 0));
  }
}

TEST(WriteIntTest, Uint8) {
  {
    Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint8_t>(123));

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(123, buffer.peekBEInt<uint8_t>());
  }
}

TEST(WriteIntTest, Uint32) {
  {
    Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint32_t>(12345));

    EXPECT_EQ(4, buffer.length());
    EXPECT_EQ(12345, buffer.peekBEInt<uint32_t>());
  }
}

TEST(WriteIntTest, SshMessageType) {
  {
    Buffer::OwnedImpl buffer;
    write(buffer, static_cast<SshMessageType>(50));

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(SshMessageType(50), buffer.peekBEInt<SshMessageType>());
  }
}

TEST(WriteIntTest, Bool) {
  {
    Buffer::OwnedImpl buffer;
    write(buffer, true);

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(1, buffer.peekBEInt<uint8_t>());
  }
  {
    Buffer::OwnedImpl buffer;
    write(buffer, false);

    EXPECT_EQ(1, buffer.length());
    EXPECT_EQ(0, buffer.peekBEInt<uint8_t>());
  }
}

template <typename T>
class ReadWriteIntTest : public testing::Test {};

using BasicFieldTypes = Types<uint8_t, uint32_t, uint64_t, SshMessageType>;
TYPED_TEST_SUITE(ReadWriteIntTest, BasicFieldTypes);

TYPED_TEST(ReadWriteIntTest, ReadWrite) {
  Buffer::OwnedImpl buffer;
  TypeParam in = ~static_cast<TypeParam>(0);
  EXPECT_NO_THROW({
    auto n = write(buffer, in);
    EXPECT_EQ(sizeof(in), n);
  });
  EXPECT_EQ(sizeof(in), buffer.length());
  EXPECT_NO_THROW({
    TypeParam out{};
    auto n = read(buffer, out, sizeof(out));
    EXPECT_EQ(sizeof(out), n);
    EXPECT_EQ(out, in);
  });
  EXPECT_EQ(0, buffer.length());
}

TYPED_TEST(ReadWriteIntTest, ShortRead) {
  Buffer::OwnedImpl buffer;
  TypeParam in = ~static_cast<TypeParam>(0);
  EXPECT_NO_THROW({
    auto n = write(buffer, in);
    EXPECT_EQ(sizeof(in), n);
  });
  EXPECT_EQ(sizeof(in), buffer.length());
  buffer.drain(1); // drop 1 byte
  TypeParam out{};
  EXPECT_SHORT_READ(read(buffer, out, sizeof(out)));
  EXPECT_EQ(sizeof(in) - 1, buffer.length());
}

TYPED_TEST(ReadWriteIntTest, ZeroLimit) {
  Buffer::OwnedImpl buffer;
  TypeParam out{};
  EXPECT_SHORT_READ(read(buffer, out, 0));
}

template <typename T>
class ReadWriteStringsTest : public testing::Test {
protected:
  static constexpr size_t input_size = 100;
  void SetUp() override {
    input_.resize(input_size);
    RAND_bytes(reinterpret_cast<uint8_t*>(input_.data()), input_.size());
  }

  void writeInputToBuffer() {
    EXPECT_NO_THROW({
      auto n = write(this->buffer_, this->input_);
      EXPECT_EQ(this->input_.size(), n);
    });
  }

  T input_;
  Buffer::OwnedImpl buffer_;
};

TYPED_TEST_SUITE(ReadWriteStringsTest, testStringTypes);

TYPED_TEST(ReadWriteStringsTest, ReadWrite) {
  this->writeInputToBuffer();
  EXPECT_NO_THROW({
    TypeParam out{};
    auto n = read(this->buffer_, out, this->input_.size());
    EXPECT_EQ(out.size(), n);
    EXPECT_EQ(out, this->input_);
  });
  EXPECT_EQ(0, this->buffer_.length());
}

TYPED_TEST(ReadWriteStringsTest, ShortRead) {
  this->writeInputToBuffer();
  this->buffer_.drain(1); // drop 1 byte
  TypeParam out{};
  EXPECT_SHORT_READ(read(this->buffer_, out, this->input_.size()));
  EXPECT_EQ(this->input_.size() - 1, this->buffer_.length());
}

TYPED_TEST(ReadWriteStringsTest, ZeroLength) {
  // empty buffer
  EXPECT_NO_THROW({
    TypeParam out;
    auto n = read(this->buffer_, out, 0);
    EXPECT_EQ(0, n);
    EXPECT_EQ(this->buffer_.length(), 0);
  });
  // non-empty buffer
  this->writeInputToBuffer();
  EXPECT_NO_THROW({
    TypeParam out;
    auto n = read(this->buffer_, out, 0);
    EXPECT_EQ(0, n);
    EXPECT_EQ(this->buffer_.length(), TestFixture::input_size);
  });
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_LengthPrefixed) {
  this->buffer_.template writeBEInt<uint32_t>(this->input_size);
  this->writeInputToBuffer();
  TypeParam out{};
  // read length prefixed string
  EXPECT_NO_THROW({
    auto n = read_opt<LengthPrefixed>(this->buffer_, out, static_cast<size_t>(this->buffer_.length()));
    EXPECT_EQ(this->input_size + 4, n);
    EXPECT_EQ(this->input_size, out.size());
  });
  // buffer should now be empty
  EXPECT_EQ(0, this->buffer_.length());
  // length-prefixed read with 0 limit should throw
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(this->buffer_, out, 0uz));
  // read with >0 limit should throw
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(this->buffer_, out, 1uz));
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_LengthPrefixed_ShortLimit) {
  this->buffer_.template writeBEInt<uint32_t>(this->input_size);
  this->writeInputToBuffer();
  EXPECT_EQ(this->input_size + 4, this->buffer_.length());
  TypeParam out{};
  // read length prefixed string with a short limit
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(this->buffer_, out, 5uz));
  EXPECT_EQ(this->input_size, this->buffer_.length());
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_None) {
  this->writeInputToBuffer();
  TypeParam out{};
  // read non-length prefixed string
  EXPECT_NO_THROW({
    auto n = read_opt<None>(this->buffer_, out, static_cast<size_t>(this->buffer_.length()));
    EXPECT_EQ(this->input_size, n);
    EXPECT_EQ(this->input_size, out.size());
  });
  // buffer should now be empty
  EXPECT_EQ(0, this->buffer_.length());
  EXPECT_NO_THROW({
    // read with 0 limit should just return 0
    EXPECT_EQ(0, read_opt<None>(this->buffer_, out, 0uz));
  });
  // read with >0 limit should throw
  EXPECT_SHORT_READ(read_opt<None>(this->buffer_, out, 1uz));
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_LengthPrefixed_LengthLargerThanBuffer) {
  this->buffer_.template writeBEInt<uint32_t>(this->input_size + 1);
  this->writeInputToBuffer();
  TypeParam out{};
  // attempt to read an entry of length [input_size+1], with only [input_size] bytes in the buffer
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(this->buffer_, out, static_cast<size_t>(this->buffer_.length())));
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_LengthPrefixed_ZeroLength) {
  this->buffer_.template writeBEInt<uint32_t>(0);
  this->writeInputToBuffer();
  TypeParam out{};
  EXPECT_NO_THROW({
    auto n = read_opt<LengthPrefixed>(this->buffer_, out, static_cast<size_t>(this->buffer_.length()));
    EXPECT_EQ(4, n);
  });
  EXPECT_EQ(this->input_size, this->buffer_.length());
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_None_ShortRead) {
  TypeParam out{};
  EXPECT_SHORT_READ(read_opt<None>(this->buffer_, out, 1uz));
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_LengthPrefixed_ZeroLimit) {
  this->writeInputToBuffer();
  TypeParam out{};
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(this->buffer_, out, 0uz))
  EXPECT_EQ(this->input_size, this->buffer_.length());
}

TYPED_TEST(ReadWriteStringsTest, ReadOpt_None_ZeroLimit) {
  this->writeInputToBuffer();
  TypeParam out{};
  EXPECT_NO_THROW({
    auto n = read_opt<None>(this->buffer_, out, 0uz);
    EXPECT_EQ(0, n);
  });
  EXPECT_EQ(this->input_size, this->buffer_.length());
}

template <typename T>
class ReadWriteArraysTest : public testing::Test {};

using testArrayTypes = Types<fixed_bytes<1>, fixed_bytes<2>, fixed_bytes<8>, fixed_bytes<16>, fixed_bytes<32>, fixed_bytes<64>>;
TYPED_TEST_SUITE(ReadWriteArraysTest, testArrayTypes);

TYPED_TEST(ReadWriteArraysTest, ReadWrite) {
  Buffer::OwnedImpl buffer;
  TypeParam in;
  RAND_bytes(reinterpret_cast<uint8_t*>(in.data()), in.size());
  EXPECT_NO_THROW({
    auto r = write(buffer, in);
    EXPECT_EQ(in.size(), r);
  });
  EXPECT_EQ(in.size(), buffer.length());
  EXPECT_NO_THROW({
    TypeParam out{};
    auto r = read(buffer, out, in.size());
    EXPECT_EQ(out.size(), r);
    EXPECT_EQ(out, in);
  });
  EXPECT_EQ(0, buffer.length());
}

TYPED_TEST(ReadWriteArraysTest, ShortRead) {
  Buffer::OwnedImpl buffer;
  TypeParam in;
  RAND_bytes(reinterpret_cast<uint8_t*>(in.data()), in.size());
  EXPECT_NO_THROW({
    auto r = write(buffer, in);
    EXPECT_EQ(in.size(), r);
  });
  EXPECT_EQ(in.size(), buffer.length());
  {
    buffer.drain(1); // drop 1 byte
    TypeParam out{};
    EXPECT_SHORT_READ(read(buffer, out, in.size()));
    EXPECT_EQ(in.size() - 1, buffer.length());
  }
}

TYPED_TEST(ReadWriteArraysTest, IncompleteRead) {
  Buffer::OwnedImpl buffer;
  TypeParam in;
  RAND_bytes(reinterpret_cast<uint8_t*>(in.data()), in.size());
  EXPECT_NO_THROW({
    auto r = write(buffer, in);
    EXPECT_EQ(in.size(), r);
  });

  TypeParam out{};
  EXPECT_THROW_WITH_MESSAGE(read(buffer, out, in.size() - 1),
                            EnvoyException,
                            "incomplete read into fixed-size array");
  EXPECT_EQ(in.size(), buffer.length());
}

TEST(ReadOptTest, OptNone) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(12345);
  uint32_t out{};
  EXPECT_NO_THROW({
    auto n = read_opt<None>(buffer, out, 4uz);
    EXPECT_EQ(4, n);
  });
  EXPECT_EQ(0, buffer.length());
  EXPECT_EQ(12345, out);
}

TEST(ReadOptTest, OptNone_ShortRead) {
  Buffer::OwnedImpl buffer;
  uint32_t out{};

  EXPECT_SHORT_READ(read_opt<None>(buffer, out, 4uz));
}

TEST(ReadOptTest, OptNone_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  uint32_t out{};
  EXPECT_NO_THROW({
    EXPECT_EQ(0, read_opt<None>(buffer, out, 0uz));
  });
}

TEST(ReadOptTest, OptLengthPrefixed) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(12345);
  uint32_t out{};
  EXPECT_NO_THROW({
    auto n = read_opt<LengthPrefixed>(buffer, out, 8uz);
    EXPECT_EQ(8, n);
  });
  EXPECT_EQ(0, buffer.length());
  EXPECT_EQ(12345, out);
}

TEST(ReadOptTest, OptLengthPrefixed_ShortLimit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(12345);
  uint32_t out{};
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(buffer, out, 4uz));
  EXPECT_EQ(4, buffer.length());
  EXPECT_EQ(0, out);
}

TEST(ReadOptTest, OptLengthPrefixed_ShortRead) {
  Buffer::OwnedImpl buffer;
  uint32_t out{};
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(buffer, out, 4uz));
}

TEST(ReadOptTest, OptLengthPrefixed_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  uint32_t out{};
  EXPECT_SHORT_READ(read_opt<LengthPrefixed>(buffer, out, 0uz));
}

TEST(WriteOptTest, OptLengthPrefixed) {
  Buffer::OwnedImpl buffer;
  auto r = write_opt<LengthPrefixed>(buffer, static_cast<uint32_t>(12345));
  EXPECT_EQ(8, r);
  EXPECT_EQ(8, buffer.length());
  EXPECT_EQ(4, buffer.drainBEInt<uint32_t>());
  EXPECT_EQ(12345, buffer.drainBEInt<uint32_t>());
}

TEST(WriteOptTest, OptNone) {
  Buffer::OwnedImpl buffer;
  auto r = write_opt<None>(buffer, static_cast<uint32_t>(12345));
  EXPECT_EQ(4, r);
  EXPECT_EQ(4, buffer.length());
  EXPECT_EQ(12345, buffer.drainBEInt<uint32_t>());
}

TEST(ReadOptTest, List_OptNone_EmptyBuffer) {
  Buffer::OwnedImpl buffer;

  std::vector<uint32_t> out;
  EXPECT_NO_THROW({
    auto r = read_opt<None>(buffer, out, 0);
    EXPECT_EQ(0, r);
  });
  EXPECT_SHORT_READ(read_opt<None>(buffer, out, 4));
}

TEST(ReadOptTest, List_OptNone_Read) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2, 3};
  EXPECT_NO_THROW({
    auto r = read_opt<None>(buffer, out, buffer.length());
    EXPECT_EQ(12, r);

    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptNone_ShortRead) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<None>(buffer, out, 16));
}

TEST(ReadOptTest, List_OptNone_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  EXPECT_NO_THROW({
    EXPECT_EQ(0, read_opt<None>(buffer, out, 0));
  });
  EXPECT_EQ(12, buffer.length());
}

TEST(ReadOptTest, List_OptListSizePrefixed_Read) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(3);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2, 3};
  EXPECT_NO_THROW({
    auto r = read_opt<ListSizePrefixed>(buffer, out, buffer.length());
    EXPECT_EQ(16, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListSizePrefixed_ZeroListSize) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{};
  EXPECT_NO_THROW({
    auto r = read_opt<ListSizePrefixed>(buffer, out, buffer.length());
    EXPECT_EQ(4, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListSizePrefixed_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<ListSizePrefixed>(buffer, out, 0));
  EXPECT_EQ(4, buffer.length());
}

TEST(ReadOptTest, List_OptListSizePrefixed_ShortRead) {
  Buffer::OwnedImpl buffer;

  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<ListSizePrefixed>(buffer, out, 4));
}

TEST(ReadOptTest, List_OptListSizePrefixed_Limit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(3);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);
  buffer.writeBEInt<uint32_t>(4); // extra unrelated bytes

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2, 3};
  EXPECT_NO_THROW({
    auto r = read_opt<ListSizePrefixed>(buffer, out, buffer.length());
    EXPECT_EQ(16, r);
    EXPECT_EQ(expected, out);
    EXPECT_EQ(4, buffer.length());
  });
}

TEST(ReadOptTest, List_OptListSizePrefixed_DecodedWrongListSize) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  EXPECT_THROW_WITH_MESSAGE(read_opt<ListSizePrefixed>(buffer, out, buffer.length()),
                            EnvoyException,
                            "decoded list size 3 does not match expected size 4");
}

TEST(ReadOptTest, List_OptListLengthPrefixed_Read) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(12);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2, 3};
  EXPECT_NO_THROW({
    auto r = read_opt<ListLengthPrefixed>(buffer, out, buffer.length());
    EXPECT_EQ(16, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListLengthPrefixed_ZeroLength) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{};
  EXPECT_NO_THROW({
    auto r = read_opt<ListLengthPrefixed>(buffer, out, buffer.length());
    EXPECT_EQ(4, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListLengthPrefixed_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<ListLengthPrefixed>(buffer, out, 0));
  EXPECT_EQ(4, buffer.length());
}

TEST(ReadOptTest, List_OptListLengthPrefixed_ShortRead) {
  Buffer::OwnedImpl buffer;

  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<ListLengthPrefixed>(buffer, out, 4));

  buffer.writeByte(0);
  buffer.writeByte(0);
  EXPECT_BUFFER_UNDERFLOW(read_opt<ListLengthPrefixed>(buffer, out, buffer.length()));
}

TEST(ReadOptTest, List_OptListLengthPrefixed_BufferTooSmall) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(12);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);

  std::vector<uint32_t> out;
  EXPECT_THROW_WITH_MESSAGE(read_opt<ListLengthPrefixed>(buffer, out, buffer.length()),
                            EnvoyException,
                            "invalid list length");
}

TEST(ReadOptTest, List_OptListLengthPrefixed_Limit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(12);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(3);
  buffer.writeBEInt<uint32_t>(4); // extra unrelated bytes

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2, 3};
  EXPECT_NO_THROW({
    auto r = read_opt<ListLengthPrefixed>(buffer, out, buffer.length());
    EXPECT_EQ(16, r);
    EXPECT_EQ(expected, out);
    EXPECT_EQ(4, buffer.length());
  });
}

TEST(ReadOptTest, List_OptListAndElemLengthPrefixed_Read) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(24);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(3);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2, 3};
  EXPECT_NO_THROW({
    auto r = read_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, out, buffer.length());
    EXPECT_EQ(28, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListAndElemLengthPrefixed_ZeroListLength) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{};
  EXPECT_NO_THROW({
    auto r = read_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, out, buffer.length());
    EXPECT_EQ(4, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListAndElemLengthPrefixed_ListLengthTooSmall) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(13);
  buffer.writeBEInt<uint32_t>(0);
  buffer.writeBEInt<uint32_t>(0);
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  EXPECT_THROW_WITH_MESSAGE(read_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, out, buffer.length()),
                            EnvoyException,
                            "invalid list length");
}

TEST(ReadOptTest, List_OptListAndElemLengthPrefixed_ListElemLenTooSmall) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(16);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(3);
  buffer.writeBEInt<uint32_t>(2);

  std::vector<uint32_t> out;
  EXPECT_THROW_WITH_MESSAGE(
    read_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, out, buffer.length()),
    EnvoyException,
    "short read in list element");
}

TEST(ReadOptTest, List_OptListAndElemLengthPrefixed_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(16);
  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, out, 0));
  EXPECT_EQ(4, buffer.length());
}

TEST(ReadOptTest, List_OptListAndElemLengthPrefixed_ShortRead) {
  Buffer::OwnedImpl buffer;
  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, out, 4));
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_Read) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(2);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1, 2};
  EXPECT_NO_THROW({
    auto r = read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length());
    EXPECT_EQ(20, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(2);
  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, 0));
  EXPECT_EQ(4, buffer.length());
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_ZeroListLength) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{};
  EXPECT_NO_THROW({
    auto r = read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length());
    EXPECT_EQ(4, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_ShortRead) {
  Buffer::OwnedImpl buffer;
  std::vector<uint32_t> out;
  EXPECT_SHORT_READ(read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, 4));
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_ZeroListSize) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(0);
  std::vector<uint32_t> out;
  EXPECT_NO_THROW({
    auto r = read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length());
    EXPECT_EQ(4, r);
  });
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_InvalidListSize) {
  {
    Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint32_t>(1); // impossible list size given the buffer length

    std::vector<uint32_t> out;
    EXPECT_THROW_WITH_MESSAGE(read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length()),
                              EnvoyException,
                              "invalid list size");
  }
  {
    Buffer::OwnedImpl buffer;
    buffer.writeBEInt<uint32_t>(4); // impossible size given remaining 12 bytes
    buffer.writeBEInt<uint32_t>(0);
    buffer.writeBEInt<uint32_t>(0);
    buffer.writeBEInt<uint32_t>(0);

    std::vector<uint32_t> out;
    EXPECT_THROW_WITH_MESSAGE(read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length()),
                              EnvoyException,
                              "invalid list size");
  }
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_Limit) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(4);
  buffer.writeBEInt<uint32_t>(1);
  buffer.writeBEInt<uint32_t>(4); // extra unrelated bytes

  std::vector<uint32_t> out;
  auto expected = std::vector<uint32_t>{1};
  EXPECT_NO_THROW({
    auto r = read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length());
    EXPECT_EQ(12, r);
    EXPECT_EQ(expected, out);
    EXPECT_EQ(4, buffer.length());
  });
}

TEST(ReadOptTest, List_OptListSizePrefixedAndElemLengthPrefixed_DecodedWrongListSize) {
  Buffer::OwnedImpl buffer;
  buffer.writeBEInt<uint32_t>(2);
  buffer.writeBEInt<uint32_t>(12);
  buffer.add("123456789ABC");

  std::vector<std::string> out;
  EXPECT_THROW_WITH_MESSAGE(read_opt<(ListSizePrefixed | LengthPrefixed)>(buffer, out, buffer.length()),
                            EnvoyException,
                            "decoded list size 1 does not match expected size 2");
}

TEST(ReadOptTest, List_OptCommaDelimited_Read) {
  Buffer::OwnedImpl buffer;
  buffer.add("foo,bar,baz");

  std::vector<std::string> out;
  auto expected = std::vector<std::string>{"foo", "bar", "baz"};
  EXPECT_NO_THROW({
    auto r = read_opt<CommaDelimited>(buffer, out, buffer.length());
    EXPECT_EQ(11, r);
    EXPECT_EQ(expected, out);
  });
}

TEST(ReadOptTest, List_OptCommaDelimited_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  buffer.add("foo,bar,baz");

  std::vector<std::string> out;
  EXPECT_EQ(0, read_opt<CommaDelimited>(buffer, out, 0));
  EXPECT_EQ(11, buffer.length());
}

TEST(ReadOptTest, List_OptCommaDelimited_ShortRead) {
  Buffer::OwnedImpl buffer;
  std::vector<std::string> out;
  EXPECT_SHORT_READ(read_opt<CommaDelimited>(buffer, out, 4));
}

static const std::vector<std::tuple<std::string, size_t>> comma_delimited_cases_empty_element = {
  {"foo,bar,", 3},
  {"foo,,bar", 3},
  {",foo,bar", 3},
  {",,", 3},
  {",foo,", 3},
  {"foo,,", 3},
  {",,foo", 3},
};

static const std::vector<std::tuple<std::string, size_t>> comma_delimited_cases_null_terminated_element = {
  {"foo,bar,baz\0"s, 3}, // note: embedding \0 needs the literal suffix
  {"foo,bar\0,baz"s, 3},
  {"foo\0,bar,baz"s, 3},
  {"foo\0,bar\0,baz\0"s, 3},
  {"foo\0,bar,baz\0"s, 3},
  {"foo,bar\0,baz\0"s, 3},
  {"foo\0,bar\0,baz"s, 3},
};

static const std::vector<std::tuple<std::string, size_t>> comma_delimited_cases_null_inside_element = {
  {"f\0o"s, 1},
  {"foo,b\0r"s, 2},
  {"f\0o,b\0r"s, 2},
  {"f\0o"s, 1},
  {"foo,b\0r,baz"s, 3},
};

TEST(ReadOptTest, List_OptCommaDelimited_EmptyElement) {
  for (const auto& [str, _] : comma_delimited_cases_empty_element) {
    Buffer::OwnedImpl buffer;
    buffer.add(str);
    std::vector<std::string> out;
    EXPECT_THROW_WITH_MESSAGE(read_opt<CommaDelimited>(buffer, out, buffer.length()),
                              EnvoyException,
                              "invalid empty string in comma-separated list");
  }
}

TEST(ReadOptTest, List_OptCommaDelimited_NullTerminatedElement) {
  for (const auto& [str, _] : comma_delimited_cases_null_terminated_element) {
    Buffer::OwnedImpl buffer;
    write(buffer, str);
    std::vector<std::string> out;
    EXPECT_THROW_WITH_MESSAGE(read_opt<CommaDelimited>(buffer, out, buffer.length()),
                              EnvoyException,
                              "invalid null-terminated string in comma-separated list");
  }
}

TEST(ReadOptTest, List_OptCommaDelimited_NullInsideElement) {
  for (const auto& i : comma_delimited_cases_null_inside_element) {
    auto [str, size] = i;
    Buffer::OwnedImpl buffer;
    write(buffer, str);
    std::vector<std::string> out;
    EXPECT_NO_THROW({
      auto r = read_opt<CommaDelimited>(buffer, out, buffer.length());
      EXPECT_EQ(str.size(), r);
    });
    EXPECT_EQ(size, out.size());
  }
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_Read) { // aka NameListFormat
  Buffer::OwnedImpl buffer;
  write(buffer, static_cast<uint32_t>(11)); // length
  write_opt<None>(buffer, "foo,bar,baz"s);

  string_list out;
  EXPECT_NO_THROW({
    auto r = read_opt<NameListFormat>(buffer, out, buffer.length());
    EXPECT_EQ(15, r);
  });
  auto expected = string_list{"foo", "bar", "baz"};
  EXPECT_EQ(expected, out);
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_ZeroLimit) {
  Buffer::OwnedImpl buffer;
  write(buffer, static_cast<uint32_t>(11)); // length
  write_opt<None>(buffer, "foo,bar,baz"s);

  string_list out;
  EXPECT_SHORT_READ(read_opt<NameListFormat>(buffer, out, 0));
  EXPECT_EQ(15, buffer.length());
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_ExtraData) {
  Buffer::OwnedImpl buffer;
  write(buffer, static_cast<uint32_t>(9)); // short length
  write_opt<None>(buffer, "foo,bar,baz"s); // the "az" will not be read

  string_list out;
  EXPECT_NO_THROW({
    auto r = read_opt<NameListFormat>(buffer, out, buffer.length());
    EXPECT_EQ(13, r);
  });
  auto expected = string_list{"foo", "bar", "b"};
  EXPECT_EQ(expected, out);
  EXPECT_EQ(2, buffer.length());
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_ShortRead) {
  Buffer::OwnedImpl buffer;
  write(buffer, static_cast<uint32_t>(12)); // length too large
  write_opt<None>(buffer, "foo,bar,baz"s);

  string_list out;
  EXPECT_THROW_WITH_MESSAGE(read_opt<NameListFormat>(buffer, out, buffer.length()),
                            EnvoyException,
                            "invalid list length");
  EXPECT_EQ(11, buffer.length());
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_ZeroListLength) {
  Buffer::OwnedImpl buffer;
  write(buffer, static_cast<uint32_t>(0)); // zero length
  write_opt<None>(buffer, "foo,bar,baz"s); // unrelated data

  string_list out;
  EXPECT_NO_THROW({
    auto r = read_opt<NameListFormat>(buffer, out, buffer.length());
    EXPECT_EQ(4, r);
  });
  EXPECT_TRUE(out.empty());
  EXPECT_EQ(11, buffer.length());
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_EmptyElement) {
  for (const auto& [str, size] : comma_delimited_cases_empty_element) {
    Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint32_t>(str.size()));
    write_opt<None>(buffer, str);
    std::vector<std::string> out;
    EXPECT_THROW_WITH_MESSAGE(read_opt<NameListFormat>(buffer, out, buffer.length()),
                              EnvoyException,
                              "invalid empty string in comma-separated list");
  }
}

TEST(ReadOptTest, List_OptListLengthPrefixedAndCommaDelimited_NullTerminatedElement) {
  for (const auto& [str, size] : comma_delimited_cases_null_terminated_element) {
    Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint32_t>(str.size()));
    EXPECT_EQ(str.size(), write_opt<None>(buffer, str));
    std::vector<std::string> out;
    EXPECT_THROW_WITH_MESSAGE(read_opt<NameListFormat>(buffer, out, buffer.length()),
                              EnvoyException,
                              "invalid null-terminated string in comma-separated list");
  }
}

TEST(ReadOptTest, List_OptOptListLengthPrefixedAndCommaDelimited_NullInsideElement) {
  for (const auto& i : comma_delimited_cases_null_inside_element) {
    auto [str, size] = i;
    Buffer::OwnedImpl buffer;
    write(buffer, static_cast<uint32_t>(str.size()));
    EXPECT_EQ(str.size(), write_opt<None>(buffer, str));
    std::vector<std::string> out;
    EXPECT_NO_THROW({
      auto r = read_opt<NameListFormat>(buffer, out, buffer.length());
      EXPECT_EQ(str.size() + 4, r);
    });
    EXPECT_EQ(size, out.size());
  }
}

TEST(ReadOptTest, ZeroLength) {
  Buffer::OwnedImpl buffer;
  bytes out;
  EXPECT_NO_THROW({
    auto n = read_opt<None>(buffer, out, static_cast<size_t>(buffer.length()));
    EXPECT_EQ(0, n);
    EXPECT_EQ(0, out.size());
  });
  buffer.writeByte(1);
  buffer.writeByte(2);
  buffer.writeByte(3);
  EXPECT_NO_THROW({
    auto n = read_opt<None>(buffer, out, static_cast<size_t>(buffer.length()));
    EXPECT_EQ(3, n);
    EXPECT_EQ(3, out.size());
  });
}

TEST(WriteOptTest, List_OptNone_Write) {
  Buffer::OwnedImpl buffer;
  write_opt<None>(buffer, std::vector<uint32_t>{1, 2, 3});
  EXPECT_EQ(12, buffer.length());
  EXPECT_EQ(1, buffer.peekBEInt<uint32_t>(0));
  EXPECT_EQ(2, buffer.peekBEInt<uint32_t>(4));
  EXPECT_EQ(3, buffer.peekBEInt<uint32_t>(8));
}

TEST(WriteOptTest, List_OptListSizePrefixed_Write) {
  Buffer::OwnedImpl buffer;
  write_opt<ListSizePrefixed>(buffer, std::vector<uint32_t>{1, 2, 3});
  EXPECT_EQ(16, buffer.length());
  EXPECT_EQ(3, buffer.peekBEInt<uint32_t>(0));
  EXPECT_EQ(1, buffer.peekBEInt<uint32_t>(4));
  EXPECT_EQ(2, buffer.peekBEInt<uint32_t>(8));
  EXPECT_EQ(3, buffer.peekBEInt<uint32_t>(12));
}

TEST(WriteOptTest, List_OptListLengthPrefixed_Write) {
  Buffer::OwnedImpl buffer;
  write_opt<ListLengthPrefixed>(buffer, std::vector<uint32_t>{1, 2, 3});
  EXPECT_EQ(16, buffer.length());
  EXPECT_EQ(12, buffer.peekBEInt<uint32_t>(0));
  EXPECT_EQ(1, buffer.peekBEInt<uint32_t>(4));
  EXPECT_EQ(2, buffer.peekBEInt<uint32_t>(8));
  EXPECT_EQ(3, buffer.peekBEInt<uint32_t>(12));
}

TEST(WriteOptTest, List_OptListLengthAndElemLengthPrefixed_Write) {
  Buffer::OwnedImpl buffer;
  write_opt<(ListLengthPrefixed | LengthPrefixed)>(buffer, std::vector<uint32_t>{1, 2, 3});
  EXPECT_EQ(28, buffer.length());
  EXPECT_EQ(24, buffer.peekBEInt<uint32_t>(0));
  EXPECT_EQ(4, buffer.peekBEInt<uint32_t>(4));
  EXPECT_EQ(1, buffer.peekBEInt<uint32_t>(8));
  EXPECT_EQ(4, buffer.peekBEInt<uint32_t>(12));
  EXPECT_EQ(2, buffer.peekBEInt<uint32_t>(16));
  EXPECT_EQ(4, buffer.peekBEInt<uint32_t>(20));
  EXPECT_EQ(3, buffer.peekBEInt<uint32_t>(24));
}

TEST(WriteOptTest, List_OptCommaDelimited_Write) {
  {
    Buffer::OwnedImpl buffer;
    write_opt<CommaDelimited>(buffer, std::vector<std::string>{"foo", "bar", "baz"});
    EXPECT_EQ(11, buffer.length());
    EXPECT_EQ("foo,bar,baz", buffer.toString());
  }
  {
    Buffer::OwnedImpl buffer;
    write_opt<CommaDelimited>(buffer, std::vector<std::string>{"foo"});
    EXPECT_EQ(3, buffer.length());
    EXPECT_EQ("foo", buffer.toString());
  }
  {
    Buffer::OwnedImpl buffer;
    write_opt<CommaDelimited>(buffer, std::vector<std::string>{});
    EXPECT_EQ(0, buffer.length());
  }
}

TEST(WriteOptTest, List_OptCommaDelimited_EmptyListElement) {
  Buffer::OwnedImpl buffer;
  EXPECT_THROW_WITH_MESSAGE(
    write_opt<CommaDelimited>(buffer, std::vector<std::string>{"foo", ""}),
    EnvoyException,
    "invalid empty string in comma-separated list");
}

TEST(WriteOptTest, List_OptCommaDelimited_Empty) {
  Buffer::OwnedImpl buffer;
  EXPECT_EQ(0, write_opt<CommaDelimited>(buffer, std::vector<std::string>{}));
  EXPECT_EQ(0, buffer.length());
}

static_assert((ListLengthPrefixed | CommaDelimited) == NameListFormat);
TEST(WriteOptTest, List_OptListLengthPrefixedAndCommaDelimited_Write) { // aka NameListFormat
  {
    Buffer::OwnedImpl buffer;
    write_opt<(ListLengthPrefixed | CommaDelimited)>(buffer, std::vector<std::string>{"foo", "bar", "baz"});
    EXPECT_EQ(15, buffer.length());
    EXPECT_EQ("\x00\x00\x00\x0B"
              "foo,bar,baz"s,
              buffer.toString());
  }
  {
    Buffer::OwnedImpl buffer;
    write_opt<(ListLengthPrefixed | CommaDelimited)>(buffer, std::vector<std::string>{"foo"});
    EXPECT_EQ(7, buffer.length());
    EXPECT_EQ("\x00\x00\x00\x03"
              "foo"s,
              buffer.toString());
  }
  {
    Buffer::OwnedImpl buffer;
    write_opt<(ListLengthPrefixed | CommaDelimited)>(buffer, std::vector<std::string>{});
    EXPECT_EQ(4, buffer.length());
  }
}

TEST(WriteOptTest, List_OptListLengthPrefixedAndCommaDelimited_EmptyListElement) {
  Buffer::OwnedImpl buffer;
  EXPECT_THROW_WITH_MESSAGE(
    write_opt<(ListLengthPrefixed | CommaDelimited)>(buffer, std::vector<std::string>{"foo", ""}),
    EnvoyException,
    "invalid empty string in comma-separated list");
}

TEST(EncodeSequenceTest, Basic) {
  MockEncoder f1;
  EXPECT_CALL(f1, encode(_)).WillOnce(Invoke([&](Buffer::Instance& buf) {
    return write(buf, static_cast<uint32_t>(5));
  }));
  MockEncoder f2;
  EXPECT_CALL(f2, encode(_)).WillOnce(Invoke([&](Buffer::Instance& buf) {
    return write_opt<LengthPrefixed>(buf, "test"s);
  }));
  Buffer::OwnedImpl buffer;
  auto r = encodeSequence(buffer, f1, f2);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(12, *r);
  EXPECT_EQ(12, buffer.length());
}

TEST(EncodeSequenceTest, Error) {
  MockEncoder f1;
  EXPECT_CALL(f1, encode(_)).WillRepeatedly(Invoke([&](Buffer::Instance& buf) {
    return write(buf, static_cast<uint32_t>(5));
  }));
  MockEncoder f2;
  EXPECT_CALL(f2, encode(_)).WillRepeatedly(Invoke([&](Buffer::Instance& buf) {
    return write_opt<LengthPrefixed>(buf, "test"s);
  }));
  MockEncoder f3;
  EXPECT_CALL(f3, encode(_)).WillRepeatedly(Return(absl::InternalError("test")));
  {
    Buffer::OwnedImpl buffer;
    auto r = encodeSequence(buffer, f1, f2, f3);
    EXPECT_FALSE(r.ok());
  }
  {
    Buffer::OwnedImpl buffer;
    auto r = encodeSequence(buffer, f1, f3, f2);
    EXPECT_FALSE(r.ok());
  }
  {
    Buffer::OwnedImpl buffer;
    auto r = encodeSequence(buffer, f3, f1, f2);
    EXPECT_FALSE(r.ok());
  }
}

TEST(EncodeSequenceTest, MaxMessageSize) {
  MockEncoder f1;
  EXPECT_CALL(f1, encode(_)).WillRepeatedly(Invoke([&](Buffer::Instance& buf) {
    std::string big_data;
    big_data.resize(MaxPacketSize / 4);
    buf.add(big_data);
    return MaxPacketSize / 4;
  }));
  Buffer::OwnedImpl buffer;
  auto r = encodeSequence(buffer, f1, f1, f1, f1, f1);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ("message size too large", r.status().message());
}

TEST(EncodeSequenceTest, NoValidation) {
  Buffer::OwnedImpl buffer;
  MockEncoder f1;
  EXPECT_CALL(f1, encode(_)).WillOnce(Invoke([&](Buffer::Instance& buf) {
    buf.writeByte(1);
    return 1;
  }));

  auto r = encodeSequence(buffer, tags::no_validation{}, f1); // this is ok if it compiles
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(1, *r);
}

TEST(DecodeSequenceTest, Basic) {
  Buffer::OwnedImpl buffer;
  buffer.add(bytes{0, 0, 0, 5, 0, 0, 0, 4, 't', 'e', 's', 't'}.data(), 12);
  MockEncoder f1;
  EXPECT_CALL(f1, decode(_, _)).WillRepeatedly(Invoke([&](Buffer::Instance& buf, size_t len) {
    uint32_t out{};
    auto n = read(buf, out, len);
    EXPECT_EQ(5, out);
    return n;
  }));
  MockEncoder f2;
  EXPECT_CALL(f2, decode(_, _)).WillRepeatedly(Invoke([&](Buffer::Instance& buf, size_t len) {
    std::string out;
    auto n = read_opt<LengthPrefixed>(buf, out, len);
    EXPECT_EQ("test", out);
    return n;
  }));
  auto r = decodeSequence(buffer, static_cast<size_t>(buffer.length()), f1, f2);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(12, *r);
  EXPECT_EQ(0, buffer.length());
}

TEST(DecodeSequenceTest, Error) {
  MockEncoder f1;
  EXPECT_CALL(f1, decode(_, _)).WillRepeatedly(Invoke([&](Buffer::Instance& buf, size_t len) {
    uint32_t out{};
    return read(buf, out, len);
  }));
  MockEncoder f2;
  EXPECT_CALL(f2, decode(_, _)).WillRepeatedly(Invoke([&](Buffer::Instance& buf, size_t len) {
    std::string out;
    return read_opt<LengthPrefixed>(buf, out, len);
  }));
  MockEncoder f3;
  EXPECT_CALL(f3, decode(_, _)).WillRepeatedly(Return(absl::InternalError("test")));
  auto encodedData = bytes{0, 0, 0, 5, 0, 0, 0, 4, 't', 'e', 's', 't'};

  {
    Buffer::OwnedImpl buffer;
    buffer.add(encodedData.data(), encodedData.size());
    auto r = decodeSequence(buffer, static_cast<size_t>(buffer.length()), f1, f2, f3);
    EXPECT_FALSE(r.ok());
  }
  {
    Buffer::OwnedImpl buffer;
    buffer.add(encodedData.data(), encodedData.size());
    auto r = decodeSequence(buffer, static_cast<size_t>(buffer.length()), f1, f3, f2);
    EXPECT_FALSE(r.ok());
  }
  {
    Buffer::OwnedImpl buffer;
    buffer.add(encodedData.data(), encodedData.size());
    auto r = decodeSequence(buffer, static_cast<size_t>(buffer.length()), f3, f1, f2);
    EXPECT_FALSE(r.ok());
  }
}

TEST(DecodeSequenceTest, NoValidation) {
  Buffer::OwnedImpl buffer;
  write(buffer, static_cast<uint32_t>(1));
  MockEncoder f1;
  EXPECT_CALL(f1, decode(_, _)).WillOnce(Invoke([&](Buffer::Instance& buf, size_t len) {
    uint32_t out{};
    auto n = read(buf, out, len);
    EXPECT_EQ(1, out);
    return n;
  }));

  auto r = decodeSequence(buffer, static_cast<size_t>(buffer.length()),
                          wire::tags::no_validation{}, f1); // this is ok if it compiles
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(4, *r);
  EXPECT_EQ(0, buffer.length());
}

TEST(EncodeSequenceTest, EmptySequence) {
  Buffer::OwnedImpl buffer;

  auto r = encodeSequence(buffer);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(0, *r);
}

TEST(DecodeSequenceTest, ShortRead) {
  MockEncoder f1;
  Buffer::OwnedImpl buffer;

  auto r = decodeSequence(buffer, 1uz, f1);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().message(), "short read");
}

TEST(DecodeSequenceTest, IncompleteRead) {
  MockEncoder lpstr;
  EXPECT_CALL(lpstr, decode(_, _)).WillRepeatedly(Invoke([&](Buffer::Instance& buf, size_t len) {
    std::string s;
    size_t n{};
    try {
      n = read_opt<LengthPrefixed>(buf, s, len);
    } catch (const Envoy::EnvoyException& e) {
      return absl::StatusOr<size_t>{absl::InvalidArgumentError(e.what())};
    }
    return absl::StatusOr<size_t>{n};
  }));
  MockEncoder str;
  EXPECT_CALL(str, decode(_, _)).WillRepeatedly(Invoke([&](Buffer::Instance& buf, size_t len) {
    std::string s;
    size_t n{};
    try {
      n = read_opt<None>(buf, s, len);
    } catch (const Envoy::EnvoyException& e) {
      return absl::StatusOr<size_t>{absl::InvalidArgumentError(e.what())};
    }
    return absl::StatusOr<size_t>{n};
  }));

  {
    Buffer::OwnedImpl buf;
    write_opt<LengthPrefixed>(buf, "str1"s);
    write_opt<LengthPrefixed>(buf, "str2"s);
    write_opt<LengthPrefixed>(buf, "str3"s);

    auto r = decodeSequence(buf, static_cast<size_t>(buf.length()), lpstr, lpstr, lpstr, lpstr);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "short read");
  }

  {
    Buffer::OwnedImpl buf;
    write_opt<LengthPrefixed>(buf, "str1"s);
    write_opt<LengthPrefixed>(buf, "str2"s);
    write_opt<LengthPrefixed>(buf, "str3"s);

    // reading the second string as non-length-prefixed will consume str3, and cause a short read
    auto r = decodeSequence(buf, static_cast<size_t>(buf.length()), lpstr, str, lpstr);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "short read");
  }

  {
    Buffer::OwnedImpl buf;
    auto r = decodeSequence(buf, static_cast<size_t>(buf.length()), lpstr, lpstr, lpstr, lpstr);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "short read");
  }
  {
    Buffer::OwnedImpl buf;
    auto r = decodeSequence(buf, static_cast<size_t>(buf.length()), lpstr);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.status().message(), "short read");
  }
}

TEST(DecodeSequenceTest, ZeroLimit) {
  MockEncoder f1;
  EXPECT_CALL(f1, decode(_, 0uz)).WillOnce(Return(absl::StatusOr<size_t>{0uz}));
  Buffer::OwnedImpl buffer;

  auto r = decodeSequence(buffer, 0uz, f1);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(0, *r);
}

TEST(DecodeSequenceTest, EmptySequence) {
  Buffer::OwnedImpl buffer;

  auto r = decodeSequence(buffer, 0uz);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(0, *r);

  r = decodeSequence(buffer, 1uz); // should be a no-op regardless of limit
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(0, *r);
}

} // namespace wire::test