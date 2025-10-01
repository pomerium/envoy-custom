#include "source/extensions/filters/network/ssh/socks5.h"
#include "test/test_common/test_common.h"
#include "test/test_common/utility.h"
#include "source/common/network/utility.h"
#include "source/common/network/address_impl.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class MockSocks5ChannelCallbacks : public Socks5ChannelCallbacks {
public:
  MOCK_METHOD(void, writeChannelData, (bytes&&));
};

static const auto AddressParams = testing::ValuesIn(std::vector<std::pair<envoy::config::core::v3::Address, bytes>>{
  {
    [] {
      envoy::config::core::v3::Address a;
      *a.mutable_socket_address()->mutable_address() = "127.0.0.1";
      a.mutable_socket_address()->set_port_value(12345);
      return a;
    }(),
    "\x05\x01\x00"
    "\x01\x7F\x00\x00\x01" // 127.0.0.1
    "\x30\x39"_bytes,      // 12345
  },
  {
    [] {
      envoy::config::core::v3::Address a;
      *a.mutable_socket_address()->mutable_address() = "::1";
      a.mutable_socket_address()->set_port_value(100);
      return a;
    }(),
    "\x05\x01\x00"
    "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" // ::1
    "\x00\x64"_bytes,                                                      // 100
  },
  {
    [] {
      envoy::config::core::v3::Address a;
      *a.mutable_socket_address()->mutable_address() = "example.com";
      a.mutable_socket_address()->set_port_value(443);
      return a;
    }(),
    "\x05\x01\x00"
    "\x03\x{0B}example.com" // "example.com"
    "\x01\xBB"_bytes,       // 443
  },
});
static const auto AddressParamNames = TestParameterNames({"ipv4", "ipv6", "fqdn"});

class MethodSelectionTest : public testing::TestWithParam<
                              std::pair<envoy::config::core::v3::Address, bytes>> {
public:
  void SetUp() override {
    std::tie(*address_, expected_connect_request_) = GetParam();
    EXPECT_CALL(callbacks_, writeChannelData("\x05\x01\x00"_bytes));
    handshaker_.startHandshake();
    testing::Mock::VerifyAndClearExpectations(&callbacks_);
  }

  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks_;
  std::shared_ptr<envoy::config::core::v3::Address> address_ =
    std::make_shared<envoy::config::core::v3::Address>();
  bytes expected_connect_request_;
  Socks5ClientHandshaker handshaker_{callbacks_, address_};
};

TEST_P(MethodSelectionTest, PartialReads) {
  // Test the pathological case of writing 1 byte at a time
  Buffer::OwnedImpl buffer;
  ASSERT_OK(handshaker_.readChannelData(buffer));
  ASSERT_FALSE(handshaker_.result().has_value());

  buffer.writeByte(0x05);
  ASSERT_OK(handshaker_.readChannelData(buffer));
  ASSERT_FALSE(handshaker_.result().has_value());
  ASSERT_EQ(1, buffer.length()); // should not drain any bytes yet

  buffer.writeByte(0x00);

  EXPECT_CALL(callbacks_, writeChannelData(auto(expected_connect_request_)));
  ASSERT_OK(handshaker_.readChannelData(buffer));
  ASSERT_FALSE(handshaker_.result().has_value());
  ASSERT_EQ(0, buffer.length());
}

TEST_P(MethodSelectionTest, WrongProtocol) {
  Buffer::OwnedImpl buffer;
  buffer.writeByte(0x04);
  buffer.writeByte(0x00);
  ASSERT_EQ(absl::InvalidArgumentError("socks5: invalid version"),
            handshaker_.readChannelData(buffer));
  EXPECT_EQ(2, buffer.length());
}

TEST_P(MethodSelectionTest, AuthRequired) {
  Buffer::OwnedImpl buffer;
  buffer.writeByte(0x05);
  buffer.writeByte(0xFF);
  ASSERT_EQ(absl::UnimplementedError("socks5: upstream server requires authentication"),
            handshaker_.readChannelData(buffer));
  EXPECT_EQ(2, buffer.length());
}

TEST_P(MethodSelectionTest, InvalidMethodSelection) {
  Buffer::OwnedImpl buffer;
  buffer.writeByte(0x05);
  buffer.writeByte(0x01);
  ASSERT_EQ(absl::InvalidArgumentError("socks5: unexpected method selected by server: 1"),
            handshaker_.readChannelData(buffer));
  EXPECT_EQ(2, buffer.length());
}

TEST_P(MethodSelectionTest, SendConnectRequestError) {
  Buffer::OwnedImpl buffer;
  buffer.writeByte(0x05);
  buffer.writeByte(0x00);

  auto bigUrl = absl::StrCat(std::string(255, 'a'), ".com");
  *address_->mutable_socket_address()->mutable_address() = bigUrl;
  ASSERT_EQ(absl::InvalidArgumentError("socks5: error sending connect request: domain name is limited to 255 characters"),
            handshaker_.readChannelData(buffer));
  EXPECT_EQ(2, buffer.length());
}

INSTANTIATE_TEST_SUITE_P(
  MethodSelection, MethodSelectionTest,
  AddressParams, AddressParamNames);

class ConnectRequestTest : public testing::TestWithParam<
                             std::pair<envoy::config::core::v3::Address, bytes>> {};

TEST_P(ConnectRequestTest, ConnectRequest) {
  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks;
  auto [addrProto, expectedConnectRequest] = GetParam();
  auto addr = std::make_shared<envoy::config::core::v3::Address>(addrProto);
  Socks5ClientHandshaker handshaker(callbacks, addr);
  ASSERT_FALSE(handshaker.result().has_value());

  IN_SEQUENCE;
  EXPECT_CALL(callbacks, writeChannelData("\x05\x01\x00"_bytes));
  handshaker.startHandshake();
  ASSERT_FALSE(handshaker.result().has_value());

  EXPECT_CALL(callbacks, writeChannelData(auto(expectedConnectRequest)));

  Buffer::OwnedImpl buffer("\x05\x00"sv); // string view conversion is important to keep the 0 byte
  ASSERT_OK(handshaker.readChannelData(buffer));
}

INSTANTIATE_TEST_SUITE_P(
  ConnectRequest, ConnectRequestTest,
  AddressParams, AddressParamNames);

struct partition_func {
  const char* name;
  std::function<std::vector<bytes>(const bytes&)> fn;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const partition_func& pf) { // NOLINT
    absl::Format(&sink, "partition: %s", pf.name);
  }

  decltype(auto) operator()(const bytes& b) const {
    return fn(b);
  }
};

class ConnectResponseTest : public testing::TestWithParam<
                              std::tuple<std::pair<envoy::config::core::v3::Address, // request params
                                                   bytes>,                           //

                                         std::tuple<partition_func,                                                       // response params
                                                    std::pair<bytes, absl::StatusOr<envoy::config::core::v3::Address>>>>> //
{};

TEST_P(ConnectResponseTest, DecodeConnectResponse) {
  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks;

  auto [requestParams, responseParams] = GetParam();
  auto [addrProto, expectedConnectRequest] = requestParams;
  auto [partitionFunc, responseBytesAndResult] = responseParams;
  auto [responseBytes, expectedResultOrErr] = responseBytesAndResult;

  auto addr = std::make_shared<envoy::config::core::v3::Address>(addrProto);
  Socks5ClientHandshaker handshaker(callbacks, addr);

  IN_SEQUENCE;
  EXPECT_CALL(callbacks, writeChannelData("\x05\x01\x00"_bytes));
  handshaker.startHandshake();
  {
    EXPECT_CALL(callbacks, writeChannelData(auto(expectedConnectRequest)));
    Buffer::OwnedImpl buffer("\x05\x00"sv);
    ASSERT_OK(handshaker.readChannelData(buffer));
  }

  Buffer::OwnedImpl responseBuffer;
  bool expectingError = !expectedResultOrErr.ok();
  size_t accumSize{};
  auto writes = partitionFunc(responseBytes);
  for (size_t i = 0; i < writes.size(); i++) {
    const auto& part = writes[i];
    accumSize += part.size();
    responseBuffer.add(part.data(), part.size());
    auto stat = handshaker.readChannelData(responseBuffer);
    if (expectingError) {
      if (!stat.ok() || i == writes.size() - 1) {
        // We should expect to get an error at some point
        ASSERT_EQ(expectedResultOrErr.status(), stat);
        return; // skip any remaining writes
      }
      // If we expect an error, the buffer should never be drained
      ASSERT_EQ(accumSize, responseBuffer.length());
    } else {
      // We should expect never to get an error
      ASSERT_OK(stat);

      auto res = handshaker.result();
      // We should expect to get a result at some point
      ASSERT_TRUE(res.has_value() || i < writes.size() - 1);

      if (res.has_value()) {
        // If we get a result, the buffer should be drained
        EXPECT_EQ(0, responseBuffer.length());
        envoy::config::core::v3::Address protoAddr;
        Network::Utility::addressToProtobufAddress(*res.value(), protoAddr);
        EXPECT_THAT(expectedResultOrErr.value(), ProtoEq(protoAddr));
        return; // skip any remaining writes
      }
    }
  }
}

namespace partitions {

std::vector<bytes> single(const bytes& input) {
  return std::vector<bytes>{input};
}
std::vector<bytes> splitEachByte(const bytes& input) {
  std::vector<bytes> elems;
  for (auto byte : input) {
    elems.push_back(bytes{byte});
  }
  return elems;
}
std::vector<bytes> splitAfterHeader(const bytes& input) {
  if (input.size() < 4) {
    return {input};
  }
  return {to_bytes(bytes_view(input).first(3)), to_bytes(bytes_view(input).subspan(3))};
}
std::vector<bytes> splitAfterAddressType(const bytes& input) {
  if (input.size() < 5) {
    return {input};
  }
  return {to_bytes(bytes_view(input).first(4)), to_bytes(bytes_view(input).subspan(4))};
}
std::vector<bytes> splitBeforeAndAfterAddressType(const bytes& input) {
  if (input.size() < 6) {
    return {input};
  }
  return {to_bytes(bytes_view(input).first(4)), {input[4]}, to_bytes(bytes_view(input).subspan(5))};
}
std::vector<bytes> splitBeforeLastByte(const bytes& input) {
  if (input.size() < 2) {
    return {input};
  }
  return {to_bytes(bytes_view(input).first(input.size() - 1)), {input[input.size() - 1]}};
}
std::vector<bytes> random(const bytes& input) {
  absl::BitGen rng;
  std::vector<bytes> out;
  bytes current;
  for (size_t i = 0; i < input.size(); i++) {
    uint8_t b = input[i];
    current.push_back(b);
    if (absl::Uniform(rng, 0, 100) <= 10) {
      out.push_back(std::move(current));
      current.clear();
    }
  }
  if (!current.empty()) {
    out.push_back(std::move(current));
  }
  return out;
}
} // namespace partitions

INSTANTIATE_TEST_SUITE_P(
  ConnectResponse, ConnectResponseTest,
  testing::Combine(
    AddressParams,
    testing::Combine(
      testing::ValuesIn(std::vector<partition_func>{
        {"single", partitions::single},
        {"splitEachByte", partitions::splitEachByte},
        {"splitAfterHeader", partitions::splitAfterHeader},
        {"splitAfterAddressType", partitions::splitAfterAddressType},
        {"splitBeforeAndAfterAddressType", partitions::splitBeforeAndAfterAddressType},
        {"splitBeforeLastByte", partitions::splitBeforeLastByte},
        {"random", partitions::random},
      }),
      testing::ValuesIn(std::vector<std::pair<bytes, absl::StatusOr<envoy::config::core::v3::Address>>>{
        {
          {0x05, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x64},
          [] {
            envoy::config::core::v3::Address a;
            *a.mutable_socket_address()->mutable_address() = "127.0.0.1";
            a.mutable_socket_address()->set_port_value(100);
            return a;
          }(),
        },
        {
          {0x05, 0x00, 0x00, 0x04,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
           0x30, 0x39},
          [] {
            envoy::config::core::v3::Address a;
            *a.mutable_socket_address()->mutable_address() = "::1";
            a.mutable_socket_address()->set_port_value(12345);
            return a;
          }(),
        },
        {
          {0x05, 0x00, 0x00, 0x03,
           0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
           0x30, 0x39},
          absl::UnimplementedError("unsupported address type in socks5 connect response: fqdn (3)"),
        },
        {
          {0x05, 0x00, 0x01, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x64},
          //           ^^^^ reserved field must be 0
          absl::InvalidArgumentError("malformed socks5 reply"),
        },
        {
          {0x04, 0x00, 0x01, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x64},
          //^^^ protocol version must be 5
          absl::InvalidArgumentError("invalid socks5 version"),
        },
        {
          {0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x64},
          //     ^^^^ error code 1
          absl::UnavailableError("socks5 connect request failed"),
        },
        {{0x05, 0x01}, absl::UnavailableError("socks5 connect request failed")},       // short reply (without reserved field)
        {{0x05, 0x01, 0x00}, absl::UnavailableError("socks5 connect request failed")}, // short reply (with reserved field)
        {{0x05, 0x01, 0x01}, absl::UnavailableError("socks5 connect request failed")}, // error in reserved field is ignored
        // all the other errors:
        {{0x05, 0x02}, absl::PermissionDeniedError("connection not allowed by ruleset")},
        {{0x05, 0x03}, absl::UnavailableError("network unreachable")},
        {{0x05, 0x04}, absl::UnavailableError("host unreachable")},
        {{0x05, 0x05}, absl::UnavailableError("connection refused")},
        {{0x05, 0x06}, absl::DeadlineExceededError("TTL expired")},
        {{0x05, 0x07}, absl::UnimplementedError("command not supported")},
        {{0x05, 0x08}, absl::InvalidArgumentError("address type not supported")},
        {{0x05, 0x09}, absl::InternalError("invalid error code: 9")}, // bad error code
      }))));

// Misc test cases

TEST(Socks5ClientHandshakerTest, TestBufferContainsAllData) {
  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks;

  auto addr = std::make_shared<envoy::config::core::v3::Address>();
  *addr->mutable_socket_address()->mutable_address() = "127.0.0.1";
  addr->mutable_socket_address()->set_port_value(100);
  Socks5ClientHandshaker handshaker(callbacks, addr);

  EXPECT_CALL(callbacks, writeChannelData(_)).Times(2);
  handshaker.startHandshake();

  Buffer::OwnedImpl buffer;
  buffer.add("\x05\x00"
             "\x05\x00\x00\x01\x7F\x00\x00\x01\x00\x64"sv);
  ASSERT_EQ(12, buffer.length());
  ASSERT_FALSE(handshaker.result().has_value());

  ASSERT_OK(handshaker.readChannelData(buffer));
  ASSERT_EQ(10, buffer.length());
  ASSERT_FALSE(handshaker.result().has_value());

  ASSERT_OK(handshaker.readChannelData(buffer));
  ASSERT_TRUE(handshaker.result().has_value());
  ASSERT_EQ(0, buffer.length());
}

TEST(Socks5ClientHandshakerTest, TestIpv4Unsupported) {
  auto cleanup = Network::Address::Ipv4Instance::forceProtocolUnsupportedForTest(true);
  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks;

  auto addr = std::make_shared<envoy::config::core::v3::Address>();
  *addr->mutable_socket_address()->mutable_address() = "127.0.0.1";
  addr->mutable_socket_address()->set_port_value(100);
  Socks5ClientHandshaker handshaker(callbacks, addr);

  EXPECT_CALL(callbacks, writeChannelData(_)).Times(2);
  handshaker.startHandshake();

  Buffer::OwnedImpl buffer;
  buffer.add("\x05\x00"sv);
  ASSERT_OK(handshaker.readChannelData(buffer));
  buffer.add("\x05\x00\x00\x01\x7F\x00\x00\x01\x00\x64"sv);
  ASSERT_EQ(absl::FailedPreconditionError("IPv4 addresses are not supported on this machine"),
            handshaker.readChannelData(buffer));
}

TEST(Socks5ClientHandshakerTest, TestIpv6Unsupported) {
  auto cleanup = Network::Address::Ipv6Instance::forceProtocolUnsupportedForTest(true);
  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks;

  auto addr = std::make_shared<envoy::config::core::v3::Address>();
  *addr->mutable_socket_address()->mutable_address() = "::1";
  addr->mutable_socket_address()->set_port_value(100);
  Socks5ClientHandshaker handshaker(callbacks, addr);

  EXPECT_CALL(callbacks, writeChannelData(_)).Times(2);
  handshaker.startHandshake();

  Buffer::OwnedImpl buffer;
  buffer.add("\x05\x00"sv);
  ASSERT_OK(handshaker.readChannelData(buffer));
  buffer.add("\x05\x00\x00\x04"
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
             "\x00\x64"sv);
  ASSERT_EQ(absl::FailedPreconditionError("IPv6 addresses are not supported on this machine"),
            handshaker.readChannelData(buffer));
}

TEST(Socks5ClientHandshakerTest, TestInvalidAddressType) {
  testing::StrictMock<MockSocks5ChannelCallbacks> callbacks;

  auto addr = std::make_shared<envoy::config::core::v3::Address>();
  *addr->mutable_socket_address()->mutable_address() = "::1";
  addr->mutable_socket_address()->set_port_value(100);
  Socks5ClientHandshaker handshaker(callbacks, addr);

  EXPECT_CALL(callbacks, writeChannelData(_)).Times(2);
  handshaker.startHandshake();

  Buffer::OwnedImpl buffer;
  buffer.add("\x05\x00"sv);
  ASSERT_OK(handshaker.readChannelData(buffer));
  buffer.add("\x05\x00\x00\x05"sv);
  ASSERT_EQ(absl::InvalidArgumentError("server sent invalid address type 5"),
            handshaker.readChannelData(buffer));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec