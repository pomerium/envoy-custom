#include "source/extensions/filters/network/ssh/socks5.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/network/utility.h"
#include "source/common/network/address_impl.h"
#pragma clang unsafe_buffer_usage end

#include "source/common/status.h"
#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

Socks5ClientHandshaker::Socks5ClientHandshaker(Socks5ChannelCallbacks& callbacks, std::shared_ptr<const envoy::config::core::v3::Address> address)
    : callbacks_(callbacks),
      address_(address) {}

namespace {
enum AddressType : uint8_t {
  IPv4 = 0x01,
  FQDN = 0x03,
  IPv6 = 0x04,
};
} // namespace

void Socks5ClientHandshaker::startHandshake() {
  // https://datatracker.ietf.org/doc/html/rfc1928#section-3
  ASSERT(!result_.has_value() && !received_method_selection_);

  bytes msg(3);
  msg[0] = 0x05; // Protocol version 5
  msg[1] = 0x01; // Number of auth methods (1)
  msg[2] = 0x00; // No Authentication Required

  ENVOY_LOG(debug, "sending socks5 method request");
  callbacks_.writeChannelData(std::move(msg));
}

namespace {
// Codes and message strings from https://datatracker.ietf.org/doc/html/rfc1928#section-6
absl::Status statusFromSocks5ErrorCode(uint8_t code) {
  switch (code) {
  case 0x00:
    return absl::OkStatus();
  case 0x01:
    return absl::UnavailableError("socks5 connect request failed");
  case 0x02:
    return absl::PermissionDeniedError("connection not allowed by ruleset");
  case 0x03:
    return absl::UnavailableError("network unreachable");
  case 0x04:
    return absl::UnavailableError("host unreachable");
  case 0x05:
    return absl::UnavailableError("connection refused");
  case 0x06:
    return absl::DeadlineExceededError("TTL expired");
  case 0x07:
    return absl::UnimplementedError("command not supported");
  case 0x08:
    return absl::InvalidArgumentError("address type not supported");
  default:
    return absl::InternalError(fmt::format("invalid error code: {}", code));
  }
}
} // namespace

absl::Status Socks5ClientHandshaker::readChannelData(Buffer::Instance& buffer) {
  ASSERT(!result_.has_value());
  if (!received_method_selection_) {
    return decodeMethodSelection(buffer);
  }
  return decodeConnectResponse(buffer);
}

absl::Status Socks5ClientHandshaker::decodeMethodSelection(Buffer::Instance& buffer) {
  // Method selection response
  // https://datatracker.ietf.org/doc/html/rfc1928#section-3
  //
  //  +-----+--------+
  //  | VER | METHOD |
  //  +-----+--------+
  //  |  1  |   1    |
  //  +-----+--------+

  if (buffer.length() < 2) {
    // partial read
    return absl::OkStatus();
  }
  if (buffer.peekInt<uint8_t>() != 0x05) {
    return absl::InvalidArgumentError("socks5: invalid version");
  }
  switch (auto method = buffer.peekInt<uint8_t>(1); method) {
  case 0x00:
    // Index 0 (we only request a single method)
    break;
  case 0xFF:
    return absl::UnimplementedError("socks5: upstream server requires authentication");
  default:
    return absl::InvalidArgumentError(fmt::format("socks5: unexpected method selected by server: {}", method));
  }
  ENVOY_LOG(debug, "socks5: method selection received; sending connect request");
  if (auto stat = sendConnectRequest(); !stat.ok()) {
    ENVOY_LOG(debug, "socks5: error sending connect request: {}", stat);
    return statusf("socks5: error sending connect request: {}", stat);
  }
  buffer.drain(2);
  received_method_selection_ = true;
  return absl::OkStatus();
}

absl::Status Socks5ClientHandshaker::decodeConnectResponse(Buffer::Instance& buffer) {
  // Connect response
  // https://datatracker.ietf.org/doc/html/rfc1928#section-6
  //
  //  +-----+-----+-------+------+----------+----------+
  //  | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  //  +-----+-----+-------+------+----------+----------+
  //  |  1  |  1  | X'00' |  1   | Variable |    2     |
  //  +-----+-----+-------+------+----------+----------+

  if (buffer.length() < 2) {
    // partial read
    return absl::OkStatus();
  }
  if (buffer.peekInt<uint8_t>() != 0x05) {
    return absl::InvalidArgumentError("invalid socks5 version");
  }
  auto stat = statusFromSocks5ErrorCode(buffer.peekInt<uint8_t>(1));
  if (!stat.ok()) {
    return stat;
  }
  if (buffer.length() < 3) {
    // partial read
    return absl::OkStatus();
  }
  if (auto reserved = buffer.peekInt<uint8_t>(2); reserved != 0) {
    return absl::InvalidArgumentError("malformed socks5 reply");
  }
  if (buffer.length() < 4) {
    // partial read
    return absl::OkStatus();
  }
  switch (auto addressType = buffer.peekInt<uint8_t>(3); addressType) {
  case AddressType::IPv4: {
    const size_t need = 4 + 4 + 2;
    if (buffer.length() < need) {
      // partial read
      return absl::OkStatus();
    }
    auto addr = buffer.peekInt<uint32_t, ByteOrder::Host>(4);
    auto port = buffer.peekInt<uint16_t, ByteOrder::Host>(8);
    struct sockaddr_in sockAddr{};
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = port;
    sockAddr.sin_addr.s_addr = addr;
    auto r = Network::Address::InstanceFactory::createInstancePtr<Network::Address::Ipv4Instance>(&sockAddr);
    if (!r.ok()) {
      return r.status();
    }
    buffer.drain(need);
    result_ = *r;
    return absl::OkStatus();
  };
  case AddressType::IPv6: {
    const size_t need = 4 + 16 + 2;
    if (buffer.length() < need) {
      // partial read
      return absl::OkStatus();
    }
    fixed_bytes<16> in6addr{};
    buffer.copyOut(4, 16, in6addr.data());
    auto port = buffer.peekInt<uint16_t, ByteOrder::Host>(20);
    struct sockaddr_in6 sockAddr{};
    sockAddr.sin6_family = AF_INET6;
    sockAddr.sin6_port = port;
    sockAddr.sin6_addr = std::bit_cast<struct in6_addr>(in6addr);
    auto r = Network::Address::InstanceFactory::createInstancePtr<Network::Address::Ipv6Instance>(sockAddr);
    if (!r.ok()) {
      return r.status();
    }
    buffer.drain(need);
    result_ = *r;
    return absl::OkStatus();
  };
  case AddressType::FQDN:
    return absl::UnimplementedError("unsupported address type in socks5 connect response: fqdn (3)");
  default:
    return absl::InvalidArgumentError(fmt::format("server sent invalid address type {}", addressType));
  }
}

absl::Status Socks5ClientHandshaker::sendConnectRequest() {
  // Connect request
  // https://datatracker.ietf.org/doc/html/rfc1928#section-5
  //
  //  +-----+-----+-------+------+----------+----------+
  //  | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  //  +-----+-----+-------+------+----------+----------+
  //  |  1  |  1  | X'00' |  1   | Variable |    2     |
  //  +-----+-----+-------+------+----------+----------+

  using envoy::config::core::v3::Address;
  using envoy::config::core::v3::SocketAddress;

  Buffer::OwnedImpl buffer;
  buffer.writeByte<uint8_t>(0x05); // Protocol version 5
  buffer.writeByte<uint8_t>(0x01); // Connect
  buffer.writeByte<uint8_t>(0x00); // Reserved

  std::string host = address_->socket_address().address();
  uint32_t port = address_->socket_address().port_value();

  // Try parsing an ip address.
  // NB: the object representations of the objects returned by Ipv4::address() (uint32) and
  // Ipv6::address() (absl::uint128) are the correct big-endian format for each address regardless
  // of host endianness, and can be directly added as raw bytes to the buffer.
  auto addr = Envoy::Network::Utility::parseInternetAddressNoThrow(
    host, 0, address_->socket_address().ipv4_compat());
  if (addr != nullptr && addr->ip() != nullptr) {
    switch (addr->ip()->version()) {
    case Network::Address::IpVersion::v4: {
      buffer.writeByte(AddressType::IPv4);
      auto v4 = addr->ip()->ipv4()->address();
      buffer.add(&v4, sizeof(v4));
    } break;
    case Network::Address::IpVersion::v6: {
      buffer.writeByte(AddressType::IPv6);
      auto v6 = addr->ip()->ipv6()->address();
      buffer.add(&v6, sizeof(v6));
    } break;
    }
  } else {
    buffer.writeByte(AddressType::FQDN);
    if (host.size() > 255) {
      return absl::InvalidArgumentError("domain name is limited to 255 characters");
    }
    buffer.writeByte(static_cast<uint8_t>(host.size()));
    buffer.add(std::string_view(host));
  }
  buffer.writeBEInt(static_cast<uint16_t>(port));
  callbacks_.writeChannelData(wire::flushTo<bytes>(buffer));
  return absl::OkStatus();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec