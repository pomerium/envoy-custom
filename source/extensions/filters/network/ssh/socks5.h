#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/common/network/utility.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Socks5ClientHandshaker {
public:
  Socks5ClientHandshaker(ChannelCallbacks& callbacks, std::shared_ptr<const envoy::config::core::v3::Address> address)
      : callbacks_(callbacks),
        address_(address) {}
  inline bool done() { return done_; }

  absl::Status startHandshake() {
    // https://datatracker.ietf.org/doc/html/rfc1928#section-3
    ASSERT(!done_ && !received_method_selection_);

    bytes msg(3);
    msg[0] = 0x05; // Protocol version 5
    msg[1] = 0x01; // Number of auth methods (1)
    msg[2] = 0x00; // No Authentication Required

    wire::ChannelDataMsg dataMsg;
    dataMsg.data = msg;
    dataMsg.recipient_channel = callbacks_.channelId();
    return callbacks_.sendMessageLocal(std::move(dataMsg));
  }

  absl::Status onChannelData(const wire::ChannelDataMsg& msg) {
    if (!received_method_selection_) {
      if (msg.data->size() != 2 || msg.data[0] != 0x05) {
        return absl::InvalidArgumentError("malformed SOCKS5 reply");
      }
      switch (msg.data[1]) {
      case 0x00:
        // ok
        break;
      case 0xFF:
        return absl::UnimplementedError("upstream server requires SOCKS5 authentication");
      default:
        return absl::InvalidArgumentError(fmt::format("unexpected SOCKS5 method selected by server: {}", msg.data[1]));
      }
      received_method_selection_ = true;
      return sendConnectRequest();
    }

    // connect response
    if (msg.data->size() < 7 || msg.data[0] != 0x05) {
      return absl::InvalidArgumentError("malformed SOCKS5 reply");
    }
    switch (msg.data[1]) {
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
      return absl::InternalError(fmt::format("Invalid error code: {}", msg.data[1]));
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
        buffer.writeBEInt(addr->ip()->ipv4()->address());
        break;
      case Network::Address::IpVersion::v6: {
        buffer.writeByte<uint8_t>(0x04); // IPv6
        auto v6 = addr->ip()->ipv6()->address();
        buffer.writeBEInt(absl::Uint128High64(v6));
        buffer.writeBEInt(absl::Uint128Low64(v6));
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
    wire::ChannelDataMsg dataMsg;
    dataMsg.data = wire::flushTo<bytes>(buffer);
    dataMsg.recipient_channel = callbacks_.channelId();
    return callbacks_.sendMessageLocal(std::move(dataMsg));
  }

  bool done_{false};
  bool received_method_selection_{false};
  ChannelCallbacks& callbacks_;
  std::shared_ptr<const envoy::config::core::v3::Address> address_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
