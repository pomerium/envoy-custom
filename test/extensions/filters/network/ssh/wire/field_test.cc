#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

#include "test/test_common/test_common.h"
#include "test/extensions/filters/network/ssh/wire/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"

#include <compare>

namespace wire::test {

template <typename T>
class FieldTest : public testing::Test {};

TYPED_TEST_SUITE(FieldTest, BasicFieldTypes);

TYPED_TEST(FieldTest, Operators) {
  field<TypeParam> f;
  EXPECT_EQ(TypeParam{}, f.value);
  f.value = random_value<TypeParam>();
  EXPECT_EQ(f.value, f.operator*());
  EXPECT_EQ(&f.value, f.operator->());
  TypeParam t = f;
  EXPECT_EQ(t, *f);
  EXPECT_EQ(t, f.value);
  EXPECT_EQ(t, f);
  EXPECT_EQ(f, f);
  EXPECT_EQ(std::strong_ordering::equal, t <=> f.value);
  EXPECT_EQ(std::strong_ordering::equal, t <=> f);

  t = random_value<TypeParam>();
  f = t;
  EXPECT_EQ(t, f.value);
  EXPECT_EQ(t, f.operator*());
  EXPECT_EQ(&f.value, f.operator->());

  f = random_value<TypeParam>();

  field<TypeParam> f2{f};
  EXPECT_EQ(f2.value, f.value);
  EXPECT_NE(&f2.value, &f.value);

  field<TypeParam> f3{std::move(f2)};
  EXPECT_EQ(f3.value, f.value);

  field<TypeParam> f4;
  f4 = f;
  EXPECT_EQ(f4.value, f.value);
  EXPECT_NE(&f4.value, &f.value);

  field<TypeParam> f5;
  f5 = std::move(f4);
  EXPECT_EQ(f5.value, f.value);
}

TYPED_TEST(FieldTest, Operators_ListTypes) {
  if constexpr (requires { typename TypeParam::value_type; }) {
    field<TypeParam> f;
    while (f.value.empty()) {
      f = random_value<TypeParam>();
    }
    EXPECT_EQ(f.value[0], f[0]);
    EXPECT_EQ(&f.value[0], &f[0]);
  }
}

TYPED_TEST(FieldTest, Decode) {
  Buffer::OwnedImpl buf;
  auto value = random_value<TypeParam>();
  write(buf, value);

  field<TypeParam> t;
  auto len = buf.length();
  auto r = t.decode(buf, len);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(len, *r);
  EXPECT_EQ(value, t.value);
}

TYPED_TEST(FieldTest, Decode_Error) {
  Buffer::OwnedImpl buf;
  field<TypeParam> t;
  auto r = t.decode(buf, 4);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, r.status().code());
  EXPECT_EQ("short read", r.status().message());
}

TYPED_TEST(FieldTest, Encode) {
  Buffer::OwnedImpl buf;
  auto value = random_value<TypeParam>();
  write(buf, value);
  auto encoded = flushTo<bytes>(buf);

  Buffer::OwnedImpl buf2;
  field<TypeParam> f;
  f = value;
  auto r = f.encode(buf2);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(encoded.size(), *r);
  EXPECT_EQ(encoded, flushTo<bytes>(buf2));
}

template <typename T>
class DecodeMsgTest : public testing::Test {
public:
  void SetUp() override {
    expected_type = random_value<SshMessageType>();
    expected_value = random_value<T>();
    write(buffer, expected_type);
    write(buffer, expected_value);
  }

  Buffer::OwnedImpl buffer;
  SshMessageType expected_type;
  T expected_value;
};

template <typename T>
class EncodeMsgTest : public testing::Test {
public:
  void SetUp() override {
    expected_type = random_value<SshMessageType>();
    field = random_value<T>();
  }

  Buffer::OwnedImpl buffer;
  SshMessageType expected_type;
  field<T> field;
};

TYPED_TEST_SUITE(DecodeMsgTest, BasicFieldTypes);
TYPED_TEST_SUITE(EncodeMsgTest, BasicFieldTypes);

TYPED_TEST(DecodeMsgTest, Decode) {
  field<TypeParam> field;
  size_t len = this->buffer.length();
  auto r = decodeMsg(this->buffer, this->expected_type, len, field);
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, this->buffer.length());
  EXPECT_EQ(this->expected_value, field.value);
}

TYPED_TEST(DecodeMsgTest, Decode_ZeroLimit) {
  field<TypeParam> field;
  size_t len = this->buffer.length();
  auto r = decodeMsg(this->buffer, this->expected_type, 0uz, field);
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, this->buffer.length());
}

TYPED_TEST(DecodeMsgTest, Decode_ShortRead) {
  field<TypeParam> field;
  size_t len = this->buffer.length();
  auto r = decodeMsg(this->buffer, this->expected_type, len + 1, field);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, r.status().code());
  EXPECT_EQ("short read", r.status().message());
  EXPECT_EQ(len, this->buffer.length());
}

TYPED_TEST(DecodeMsgTest, Decode_WrongMessageType) {
  field<TypeParam> field;
  size_t len = this->buffer.length();
  auto r = decodeMsg(this->buffer, ~this->expected_type, len, field);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, r.status().code());
  EXPECT_EQ(fmt::format("decoded unexpected message type {}, expected {}", this->expected_type, ~this->expected_type), r.status().message());
  EXPECT_EQ(len - 1, this->buffer.length());
}

TYPED_TEST(DecodeMsgTest, Decode_DecodeError) {
  MockEncoder enc;
  EXPECT_CALL(enc, decode(_, _))
    .WillOnce(Invoke([](Envoy::Buffer::Instance&, size_t) -> absl::StatusOr<size_t> {
      return absl::InternalError("test decode error");
    }));

  auto r = decodeMsg(this->buffer, this->expected_type, static_cast<size_t>(this->buffer.length()), enc);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, r.status().code());
  EXPECT_EQ("test decode error", r.status().message());
}

TYPED_TEST(EncodeMsgTest, Encode) {
  Buffer::OwnedImpl expected;
  write(expected, this->expected_type);
  EXPECT_TRUE(this->field.encode(expected).ok());

  Buffer::OwnedImpl buffer;
  auto r = encodeMsg(buffer, this->expected_type, this->field);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(expected.length(), *r);
  EXPECT_EQ(expected.toString(), buffer.toString());
}

TYPED_TEST(EncodeMsgTest, Encode_EncodeError) {
  MockEncoder enc;
  EXPECT_CALL(enc, encode(_))
    .WillOnce(Invoke([](Envoy::Buffer::Instance&) -> absl::StatusOr<size_t> {
      return absl::InternalError("test encode error");
    }));

  Buffer::OwnedImpl buffer;
  auto r = encodeMsg(buffer, this->expected_type, enc);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, r.status().code());
  EXPECT_EQ("test encode error", r.status().message());
}

struct TestSubMsg1 {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 1;
  static constexpr auto submsg_key_encoding = None;

  constexpr TestSubMsg1() = default;
  constexpr TestSubMsg1(uint32_t u32, uint64_t u64, const std::string& s)
      : Uint32(u32), Uint64(u64), String(s) {}

  static TestSubMsg1 random() {
    TestSubMsg1 msg;
    msg.Uint32 = random_value<uint32_t>();
    msg.String = random_value<std::string>();
    return msg;
  }

  field<uint32_t> Uint32;
  field<uint64_t> Uint64;
  field<std::string, LengthPrefixed> String;

  bool operator==(const TestSubMsg1&) const = default;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeSequence(buffer, payload_size,
                          Uint32,
                          Uint64,
                          String);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeSequence(buffer,
                          Uint32,
                          Uint64,
                          String);
  }
};

struct TestSubMsg2 {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 2;
  static constexpr auto submsg_key_encoding = None;

  constexpr TestSubMsg2() = default;
  constexpr TestSubMsg2(uint32_t u, const bytes& b)
      : Bytes(b), Uint8(u) {}

  static TestSubMsg2 random() {
    TestSubMsg2 msg;
    msg.Bytes = random_value<bytes>();
    msg.Uint8 = random_value<uint32_t>();
    return msg;
  }

  field<bytes, LengthPrefixed> Bytes;
  field<uint8_t> Uint8;

  bool operator==(const TestSubMsg2&) const = default;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeSequence(buffer, payload_size,
                          Bytes,
                          Uint8);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeSequence(buffer,
                          Bytes,
                          Uint8);
  }
};

struct TestMessage {
  using SubMsgType = sub_message<TestSubMsg1, TestSubMsg2>;
  field<std::string, LengthPrefixed> foo;
  SubMsgType request;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeMsg(buffer, SshMessageType(200), payload_size,
                     foo,
                     request.key_field(),
                     request);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeMsg(buffer, SshMessageType(200),
                     foo,
                     request.key_field(),
                     request);
  }
};

TEST(SubMessageTest, CompileTimeChecks) {
  TestMessage test_msg;

  {
    static constinit auto idx = wire::detail::sub_message_index<decltype(test_msg.foo),
                                                                decltype(test_msg.request)>();
    static_assert(idx.index == 1);
    static_assert(idx.key_field_index == -1);
  }

  {
    static constinit auto idx = wire::detail::sub_message_index<decltype(test_msg.foo),
                                                                decltype(test_msg.request)::key_field_type,
                                                                decltype(test_msg.request)>();
    static_assert(idx.index == 2);
    static_assert(idx.key_field_index == 1);
  }

  {
    static constinit auto idx = wire::detail::sub_message_index<decltype(test_msg.request)::key_field_type,
                                                                decltype(test_msg.foo),
                                                                decltype(test_msg.request)>();
    static_assert(idx.index == 2);
    static_assert(idx.key_field_index == 0);
  }

  static_assert(TestMessage::SubMsgType::has_option<TestSubMsg1>());
  static_assert(TestMessage::SubMsgType::has_option<TestSubMsg2>());

  static_assert(!TestMessage::SubMsgType::has_option<std::string>());
  static_assert(!TestMessage::SubMsgType::has_option<void>());
  static_assert(!TestMessage::SubMsgType::has_option<TestMessage>());
  static_assert(!TestMessage::SubMsgType::has_option<field<std::string>>());
  static_assert(!TestMessage::SubMsgType::has_option<TestMessage::SubMsgType>());

  static_assert(std::is_same_v<typename TestMessage::SubMsgType::key_field_type,
                               wire::detail::key_field_t<field<uint32_t, None>, TestMessage::SubMsgType>>);
}

TEST(SubMessageTest, Reset) {
  {
    TestMessage::SubMsgType msg;
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg2>());
    msg.reset(TestSubMsg1{});
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg2>());
    msg.reset(TestSubMsg2{});
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg2>());

    TestSubMsg1 msg1_l{};
    msg.reset(msg1_l);
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg2>());
    EXPECT_EQ(msg.get<TestSubMsg1>(), msg1_l);
    EXPECT_EQ(msg.get<0>(), msg1_l);
    EXPECT_EQ(TestSubMsg1::submsg_key, msg.key_field().value);

    TestSubMsg2 msg2_l{};
    msg.reset(msg2_l);
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg2>());
    EXPECT_EQ(msg.get<TestSubMsg2>(), msg2_l);
    EXPECT_EQ(msg.get<1>(), msg2_l);
    EXPECT_EQ(TestSubMsg2::submsg_key, msg.key_field().value);
  }
  {
    TestMessage::SubMsgType msg;
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg2>());
    msg = TestSubMsg1{};
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg2>());
    msg = TestSubMsg2{};
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg2>());
    TestSubMsg1 msg1_l{};
    msg = msg1_l;
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg2>());
    TestSubMsg2 msg2_l{};
    msg = msg2_l;
    EXPECT_FALSE(msg.holds_alternative<TestSubMsg1>());
    EXPECT_TRUE(msg.holds_alternative<TestSubMsg2>());
  }
}

TEST(SubMessageTest, Decode) {
  Buffer::OwnedImpl buffer;

  // message 1

  // recreate TestMessage fields
  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg1::submsg_key_encoding>(buffer, TestSubMsg1::submsg_key);

  auto msg1 = TestSubMsg1::random();
  EXPECT_TRUE(msg1.encode(buffer).ok());

  auto len = static_cast<size_t>(buffer.length());

  TestMessage msg;
  auto r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.holds_alternative<TestSubMsg1>());
  EXPECT_EQ(msg1, msg.request.get<TestSubMsg1>());

  // message 2

  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key);

  auto msg2 = TestSubMsg2::random();
  EXPECT_TRUE(msg2.encode(buffer).ok());

  len = static_cast<size_t>(buffer.length());
  r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.holds_alternative<TestSubMsg2>());
  EXPECT_EQ(msg2, msg.request.get<TestSubMsg2>());
}

TEST(SubMessageTest, Decode_Unknown) {
  Buffer::OwnedImpl buffer;

  // recreate TestMessage fields
  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  // write a key that does not correspond to one of the known sub-messages
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key + 10); // unknown key
  write_opt<LengthPrefixed>(buffer, "hello world"s);                                 // unknown message field

  auto len = static_cast<size_t>(buffer.length());
  TestMessage msg;
  auto r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_FALSE(msg.request.holds_alternative<TestSubMsg1>());
  EXPECT_FALSE(msg.request.holds_alternative<TestSubMsg2>());

  EXPECT_EQ(to_bytes("\x00\x00\x00\x0B"
                     "hello world"sv),
            *msg.request.getUnknownBytesForTest());
}

TEST(SubMessageTest, Decode_Unknown_Repeated) {
  // decode another unknown message when there is already a different unknown message stored

  TestMessage msg;
  Buffer::OwnedImpl buffer;

  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key + 10); // unknown key
  write_opt<LengthPrefixed>(buffer, "hello world"s);                                 // unknown message field

  auto len = static_cast<size_t>(buffer.length());
  auto r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.getUnknownBytesForTest().has_value());

  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key + 11); // unknown key
  write_opt<LengthPrefixed>(buffer, "foo bar"s);                                     // unknown message field
  len = static_cast<size_t>(buffer.length());

  r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());

  EXPECT_EQ(to_bytes("\x00\x00\x00\x07"
                     "foo bar"sv),
            *msg.request.getUnknownBytesForTest());
}

TEST(SubMessageTest, Decode_Unknown_Known) {
  // decode an unknown message, then decode a known message after

  TestMessage msg;
  Buffer::OwnedImpl buffer;

  // decode an unknown message
  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key + 10); // unknown key
  write_opt<LengthPrefixed>(buffer, "hello world"s);

  auto len = static_cast<size_t>(buffer.length());
  auto r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.getUnknownBytesForTest().has_value());

  // decode a known message
  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key); // known key
  auto msg2 = TestSubMsg2::random();
  EXPECT_TRUE(msg2.encode(buffer).ok());

  len = static_cast<size_t>(buffer.length());

  r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.holds_alternative<TestSubMsg2>());
  EXPECT_EQ(msg2, msg.request.get<TestSubMsg2>());

  EXPECT_FALSE(msg.request.getUnknownBytesForTest().has_value());
}

TEST(SubMessageTest, DecodeUnknown) {
  sub_message<TestSubMsg1, TestSubMsg2> submsg;

  Buffer::OwnedImpl buffer;
  TestSubMsg1 m1;
  m1.String = "hello world";
  m1.Uint32 = 0xDEADBEEF;
  m1.Uint64 = 0x1234567812345678;
  bytes expected = to_bytes("\xDE\xAD\xBE\xEF"                 // submsg.Uint32
                            "\x12\x34\x56\x78\x12\x34\x56\x78" // submsg.Uint64
                            "\x00\x00\x00\x0B"                 // len(submsg.String)
                            "hello world"s);                   // submsg.String

  EXPECT_TRUE(m1.encode(buffer).ok());

  // leave key_field unset, then decode with invalid key
  auto r = submsg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(expected.size(), *r);

  EXPECT_EQ(expected, *submsg.getUnknownBytesForTest());

  EXPECT_FALSE(submsg.holds_alternative<TestSubMsg1>());

  // decode again with key_field still unset
  r = submsg.decodeUnknown();
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(expected.size(), *r);
  EXPECT_FALSE(submsg.holds_alternative<TestSubMsg1>());

  EXPECT_EQ(expected, *submsg.getUnknownBytesForTest());

  // set key_field
  submsg.key_field() = TestSubMsg1::submsg_key;

  // decode with valid key
  r = submsg.decodeUnknown();
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(expected.size(), *r);
  EXPECT_TRUE(submsg.holds_alternative<TestSubMsg1>());
  EXPECT_EQ(m1, submsg.get<TestSubMsg1>());
  EXPECT_FALSE(submsg.getUnknownBytesForTest().has_value());
}

TEST(SubMessageTest, DecodeUnknown_KnownValue) {
  Buffer::OwnedImpl buffer;

  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg1::submsg_key_encoding>(buffer, TestSubMsg1::submsg_key);
  EXPECT_TRUE(TestSubMsg1::random().encode(buffer).ok());

  TestMessage msg;
  EXPECT_TRUE(msg.decode(buffer, buffer.length()).ok());
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.holds_alternative<TestSubMsg1>());

  EXPECT_ENVOY_BUG(msg.request.decodeUnknown().IgnoreError(), "decodeUnknown() called with known value");
}

struct SubMsg2Strings {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 1;
  static constexpr auto submsg_key_encoding = None;

  constexpr SubMsg2Strings() = default;

  field<std::string, LengthPrefixed> Str1;
  field<std::string, LengthPrefixed> Str2;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeSequence(buffer, payload_size,
                          Str1,
                          Str2);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeSequence(buffer,
                          Str1,
                          Str2);
  }
};

struct SubMsg4Strings {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 2;
  static constexpr auto submsg_key_encoding = None;

  constexpr SubMsg4Strings() = default;

  field<std::string, LengthPrefixed> Str1;
  field<std::string, LengthPrefixed> Str2;
  field<std::string, LengthPrefixed> Str3;
  field<std::string, LengthPrefixed> Str4;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeSequence(buffer, payload_size,
                          Str1,
                          Str2,
                          Str3,
                          Str4);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeSequence(buffer,
                          Str1,
                          Str2,
                          Str3,
                          Str4);
  }
};

TEST(SubMessageTest, DecodeUnknown_WrongType_NotEnoughBytes) {
  sub_message<SubMsg2Strings, SubMsg4Strings> submsg;

  Buffer::OwnedImpl buffer;
  SubMsg2Strings m1;
  m1.Str1 = random_value<std::string>();
  m1.Str2 = random_value<std::string>();
  EXPECT_TRUE(m1.encode(buffer).ok());

  ASSERT_OK(submsg.decode(buffer, buffer.length()).status());

  submsg.key_field() = SubMsg4Strings::submsg_key;
  // decode with the wrong message type, expecting to decode more fields
  auto s = submsg.decodeUnknown();
  ASSERT_FALSE(s.ok());
  EXPECT_EQ(absl::InvalidArgumentError("short read"), s.status());
}

TEST(SubMessageTest, DecodeUnknown_WrongType_TooManyBytes) {
  sub_message<SubMsg2Strings, SubMsg4Strings> submsg;

  Buffer::OwnedImpl buffer;
  SubMsg4Strings m1;
  m1.Str1 = random_value<std::string>();
  m1.Str2 = random_value<std::string>();
  m1.Str3 = random_value<std::string>();
  m1.Str4 = random_value<std::string>();
  EXPECT_TRUE(m1.encode(buffer).ok());

  auto expectedLen = static_cast<size_t>(buffer.length());
  ASSERT_OK(submsg.decode(buffer, buffer.length()).status());

  auto actualLen = [&] {
    SubMsg2Strings tmp;
    tmp.Str1 = m1.Str1;
    tmp.Str2 = m1.Str2;
    return encodeTo<bytes>(tmp)->size();
  }();

  submsg.key_field() = SubMsg2Strings::submsg_key;
  // decode with the wrong message type, expecting to decode fewer fields
  auto s = submsg.decodeUnknown();
  ASSERT_FALSE(s.ok());
  EXPECT_EQ(absl::InvalidArgumentError(fmt::format("wrong number of bytes decoded (expected {}, got {})", expectedLen, actualLen)), s.status());
}

TEST(SubMessageTest, Encode) {
  TestMessage msg;
  msg.foo = "test";
  TestSubMsg1 submsg;
  submsg.String = "hello world";
  submsg.Uint32 = 0xDEADBEEF;
  submsg.Uint64 = 0x0123456789ABCDEF;
  msg.request = submsg;
  auto encoded = encodeTo<std::string>(msg);
  EXPECT_TRUE(encoded.ok()) << encoded.status().ToString();
  EXPECT_EQ("\xC8"                             // 200
            "\x00\x00\x00\x04"                 // len(msg.foo)
            "test"                             // msg.foo
            "\x00\x00\x00\x01"                 // key field
            "\xDE\xAD\xBE\xEF"                 // submsg.Uint32
            "\x01\x23\x45\x67\x89\xAB\xCD\xEF" // submsg.Uint64
            "\x00\x00\x00\x0B"                 // len(submsg.String)
            "hello world"s,                    // submsg.String
            *encoded);
}

TEST(SubMessageTest, Encode_Empty) {
  TestMessage msg;
  msg.foo = "test";
  auto encoded = encodeTo<std::string>(msg);
  EXPECT_TRUE(encoded.ok()) << encoded.status().ToString();
  EXPECT_EQ("\xC8"               // 200
            "\x00\x00\x00\x04"   // len(msg.foo)
            "test"               // msg.foo
            "\x00\x00\x00\x00"s, // key field
            *encoded);
}

TEST(SubMessageTest, Encode_Unknown) {
  TestMessage msg;
  Buffer::OwnedImpl buffer;

  // decode an unknown message
  write(buffer, SshMessageType(200));
  write_opt<LengthPrefixed>(buffer, "test"s);
  write_opt<TestSubMsg2::submsg_key_encoding>(buffer, TestSubMsg2::submsg_key + 10); // unknown key
  write_opt<LengthPrefixed>(buffer, "hello world"s);

  auto expected = buffer.toString();

  auto len = static_cast<size_t>(buffer.length());
  auto r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());

  auto actual = encodeTo<std::string>(msg);
  EXPECT_TRUE(actual.ok()) << actual.status().ToString();

  EXPECT_EQ(expected, *actual);
}

class VisitTestSuite : public testing::Test {
public:
  void SetUp() override {
    submsg = sub_message<TestSubMsg1, TestSubMsg2>{};
    submsg.key_field() = TestSubMsg1::submsg_key;
    submsg.reset(TestSubMsg1::random());
  }

  sub_message<TestSubMsg1, TestSubMsg2> submsg;
};

template <typename T>
constexpr T& as_nonconst(const T& t) {
  return const_cast<T&>(t); // NOLINT
}

TEST(SubMessageTest, Visit) {
  enum Result {
    CalledVisitMsg1NonConst = 1,
    CalledVisitMsg1Const,
    CalledVisitMsg1RvalueRef,

    CalledVisitMsg2NonConst,
    CalledVisitMsg2Const,
    CalledVisitMsg2RvalueRef,

    CalledDefaultAutoRef,
    CalledDefaultConstAutoRef,
    CalledDefaultAutoUniversalRef,
    CalledDefaultAutoPlain,
  };

  auto visitMsg1NonConst = [](TestSubMsg1&) { return CalledVisitMsg1NonConst; };
  auto visitMsg1Const = [](const TestSubMsg1&) { return CalledVisitMsg1Const; };
  auto visitMsg1RvalueRef = [](TestSubMsg1&&) { return CalledVisitMsg1RvalueRef; };

  auto visitMsg2NonConst = [](TestSubMsg2&) { return CalledVisitMsg2NonConst; };
  auto visitMsg2Const = [](const TestSubMsg2&) { return CalledVisitMsg2Const; };

  auto defaultAutoRef = [](auto&) { return CalledDefaultAutoRef; };
  auto defaultConstAutoRef = [](const auto&) { return CalledDefaultConstAutoRef; };
  auto defaultAutoUniversalRef = [](auto&&) { return CalledDefaultAutoUniversalRef; };

  using SubMsgType = sub_message<TestSubMsg1, TestSubMsg2>;
  constexpr SubMsgType submsg1{TestSubMsg1{1, 2, "test"}};
  EXPECT_STATIC_ASSERT(as_nonconst(submsg1).visit(visitMsg1NonConst, visitMsg2NonConst) == CalledVisitMsg1NonConst);
  EXPECT_STATIC_ASSERT(as_nonconst(submsg1).visit(visitMsg1Const, visitMsg2NonConst) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(as_nonconst(submsg1).visit(visitMsg1Const, defaultConstAutoRef) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(as_nonconst(submsg1).visit(visitMsg1Const, visitMsg2Const, defaultConstAutoRef) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::move(as_nonconst(submsg1)).visit(visitMsg1RvalueRef, visitMsg2Const, defaultConstAutoRef) == CalledVisitMsg1RvalueRef);
  EXPECT_STATIC_ASSERT(std::move(as_nonconst(submsg1)).visit(visitMsg1Const, visitMsg2Const, defaultConstAutoRef) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(submsg1.visit(visitMsg1Const, visitMsg2Const) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(submsg1.visit(visitMsg1Const, visitMsg2Const) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(submsg1.visit(visitMsg1Const, defaultAutoRef) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(submsg1.visit(visitMsg1Const, defaultConstAutoRef) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(submsg1.visit(visitMsg1Const, defaultAutoUniversalRef) == CalledVisitMsg1Const);

  // void return type
  Result result{};
  submsg1.visit(
    [&result](const TestSubMsg1&) { result = CalledVisitMsg1Const; },
    [&result](const auto&) { result = CalledDefaultConstAutoRef; });
  EXPECT_EQ(CalledVisitMsg1Const, result);

  EXPECT_EQ(CalledVisitMsg1Const,
            std::visit(make_overloads_no_validation(
                         [](const TestSubMsg1&) -> Result { return CalledVisitMsg1Const; },
                         [](const auto&) -> Result { return CalledDefaultConstAutoRef; }),
                       *submsg1.oneof));

  EXPECT_EQ(CalledDefaultConstAutoRef,
            std::visit(make_overloads_no_validation(
                         [](TestSubMsg1&) -> Result { return CalledVisitMsg1Const; },
                         [](const auto&) -> Result { return CalledDefaultConstAutoRef; }),
                       *submsg1.oneof));

  EXPECT_EQ(CalledVisitMsg1Const,
            std::visit(make_overloads<basic_visitor, decltype(*submsg1.oneof)>(
                         [](const TestSubMsg1&) -> Result { return CalledVisitMsg1Const; },
                         [](const auto&) -> Result { return CalledDefaultConstAutoRef; }),
                       *submsg1.oneof));

  // no message set
  constexpr SubMsgType empty{};
  EXPECT_STATIC_ASSERT(empty.visit(visitMsg1Const, defaultAutoRef) == 0);
  // the test below is '((<visit expression>), true)' which evaluates to true if neither of the
  // visitors are hit, and doesn't compile otherwise.
  EXPECT_STATIC_ASSERT(empty.visit([](const TestSubMsg1&) { static_assert("fail"); },
                                   [](const auto&) { static_assert("fail"); }),
                       true);
}

TEST(FormatTest, FormatFields) {
  field<uint32_t> int_field = 5;
  field<std::string> str_field = "test"s;
  field<bytes> bytes_field = bytes{0xDE, 0xAD, 0xBE, 0xEF};
  EXPECT_EQ(fmt::format("{}", 5), fmt::format("{}", int_field));
  EXPECT_EQ(fmt::format("{}", "test"s), fmt::format("{}", str_field));
  EXPECT_EQ("deadbeef", fmt::format("{}", bytes_field));
}

} // namespace wire::test
