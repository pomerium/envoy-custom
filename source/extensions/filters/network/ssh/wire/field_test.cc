#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/wire_test_common.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/wire_test_util.h"
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
  auto len = this->buffer.length();
  auto r = decodeMsg(this->buffer, this->expected_type, len, field);
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, this->buffer.length());
  EXPECT_EQ(this->expected_value, field.value);
}

TYPED_TEST(DecodeMsgTest, Decode_ZeroLimit) {
  field<TypeParam> field;
  auto len = this->buffer.length();
  auto r = decodeMsg(this->buffer, this->expected_type, 0uz, field);
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, this->buffer.length());
}

TYPED_TEST(DecodeMsgTest, Decode_ShortRead) {
  field<TypeParam> field;
  auto len = this->buffer.length();
  auto r = decodeMsg(this->buffer, this->expected_type, len + 1, field);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, r.status().code());
  EXPECT_EQ("short read", r.status().message());
  EXPECT_EQ(len, this->buffer.length());
}

TYPED_TEST(DecodeMsgTest, Decode_WrongMessageType) {
  field<TypeParam> field;
  auto len = this->buffer.length();
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

  auto r = decodeMsg(this->buffer, this->expected_type, this->buffer.length(), enc);
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

  TestSubMsg1() {
    Uint32 = random_value<uint32_t>();
    String = random_value<std::string>();
  }

  field<uint32_t> Uint32;
  field<std::string, LengthPrefixed> String;

  bool operator==(const TestSubMsg1&) const = default;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeSequence(buffer, payload_size,
                          Uint32,
                          String);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeSequence(buffer,
                          Uint32,
                          String);
  }
};

struct TestSubMsg2 {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 2;
  static constexpr auto submsg_key_encoding = None;

  TestSubMsg2() {
    Uint8 = random_value<uint32_t>();
    Bytes = random_value<bytes>();
  }

  field<uint8_t> Uint8;
  field<bytes, LengthPrefixed> Bytes;

  bool operator==(const TestSubMsg2&) const = default;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
    return decodeSequence(buffer, payload_size,
                          Uint8,
                          Bytes);
  }
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return encodeSequence(buffer,
                          Uint8,
                          Bytes);
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

  TestSubMsg1 msg1{};
  EXPECT_TRUE(msg1.encode(buffer).ok());

  auto len = buffer.length();

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

  TestSubMsg2 msg2{};
  EXPECT_TRUE(msg2.encode(buffer).ok());

  len = buffer.length();
  r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok()) << r.status().ToString();
  EXPECT_EQ(len, *r);
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(msg.request.holds_alternative<TestSubMsg2>());
  EXPECT_EQ(msg2, msg.request.get<TestSubMsg2>());
}

TEST(SubMessageTest, Encode) {
}

} // namespace wire::test