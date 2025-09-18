#pragma once

#include "source/common/network/utility.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Socks5ChannelCallbacks {
public:
  virtual ~Socks5ChannelCallbacks() = default;
  virtual void sendChannelData(bytes&& bytes) PURE;
  virtual void onSocks5HandshakeComplete() PURE;
};

class Socks5ClientHandshaker {
public:
  Socks5ClientHandshaker(Socks5ChannelCallbacks& callbacks, std::shared_ptr<const envoy::config::core::v3::Address> address)
      : callbacks_(callbacks),
        address_(address) {}
  inline bool done() { return done_; }

  void startHandshake() {
    // https://datatracker.ietf.org/doc/html/rfc1928#section-3
    ASSERT(!done_ && !received_method_selection_);

    bytes msg(3);
    msg[0] = 0x05; // Protocol version 5
    msg[1] = 0x01; // Number of auth methods (1)
    msg[2] = 0x00; // No Authentication Required

    callbacks_.sendChannelData(std::move(msg));
  }

  absl::Status readChannelData(const bytes& msg) {
    if (!received_method_selection_) {
      if (msg.size() != 2 || msg[0] != 0x05) {
        return absl::InvalidArgumentError("malformed SOCKS5 reply");
      }
      switch (msg[1]) {
      case 0x00:
        // ok
        break;
      case 0xFF:
        return absl::UnimplementedError("upstream server requires SOCKS5 authentication");
      default:
        return absl::InvalidArgumentError(fmt::format("unexpected SOCKS5 method selected by server: {}", msg[1]));
      }
      received_method_selection_ = true;
      if (auto stat = sendConnectRequest(); !stat.ok()) {
        return stat;
      }
      callbacks_.onSocks5HandshakeComplete();
      return absl::OkStatus();
    }

    // connect response
    if (msg.size() < 7 || msg[0] != 0x05) {
      return absl::InvalidArgumentError("malformed SOCKS5 reply");
    }
    switch (msg[1]) {
    case 0x00:
      done_ = true;
      return absl::OkStatus();
    case 0x01:
      return absl::UnavailableError("SOCKS5 connect request failed");
    case 0x02:
      return absl::PermissionDeniedError("Connection not allowed by ruleset");
    case 0x03:
      return absl::UnavailableError("Network unreachable");
    case 0x04:
      return absl::UnavailableError("Host unreachable");
    case 0x05:
      return absl::UnavailableError("Connection refused");
    case 0x06:
      return absl::DeadlineExceededError("TTL expired");
    case 0x07:
      return absl::UnimplementedError("Command not supported");
    case 0x08:
      return absl::InvalidArgumentError("Address type not supported");
    default:
      return absl::InternalError(fmt::format("Invalid error code: {}", msg[1]));
    }
  }

private:
  absl::Status sendConnectRequest() {
    // https://datatracker.ietf.org/doc/html/rfc1928#section-5
    using envoy::config::core::v3::Address;
    using envoy::config::core::v3::SocketAddress;

    Buffer::OwnedImpl buffer;
    buffer.writeByte<uint8_t>(0x05); // Protocol version 5
    buffer.writeByte<uint8_t>(0x01); // Connect
    buffer.writeByte<uint8_t>(0x00); // Reserved

    std::string host = address_->socket_address().address();
    uint32_t port = address_->socket_address().port_value();

    // try parsing an ip address
    auto addr = Envoy::Network::Utility::parseInternetAddressNoThrow(
      host, 0, address_->socket_address().ipv4_compat());
    if (addr != nullptr && addr->ip() != nullptr) {
      switch (addr->ip()->version()) {
      case Network::Address::IpVersion::v4:
        buffer.writeByte<uint8_t>(0x01); // IPv4
        // The address is already stored in network byte order
        buffer.writeInt(addr->ip()->ipv4()->address());
        break;
      case Network::Address::IpVersion::v6: {
        buffer.writeByte<uint8_t>(0x04); // IPv6
        auto v6 = addr->ip()->ipv6()->address();
        // Same as above, don't need to byteswap here
        buffer.writeInt(absl::Uint128Low64(v6));
        buffer.writeInt(absl::Uint128High64(v6));
      } break;
      }
    } else {
      buffer.writeByte<uint8_t>(0x04); // Domain name
      if (host.size() > 255) {
        return absl::InvalidArgumentError("domain name is limited to 255 characters");
      }
      buffer.writeByte(static_cast<uint8_t>(host.size()));
      buffer.add(std::string_view(host));
    }
    buffer.writeBEInt(static_cast<uint16_t>(port));
    callbacks_.sendChannelData(wire::flushTo<bytes>(buffer));
    return absl::OkStatus();
  }

  bool done_{false};
  bool received_method_selection_{false};
  Socks5ChannelCallbacks& callbacks_;
  std::shared_ptr<const envoy::config::core::v3::Address> address_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
