#pragma once

#include "source/common/types.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/network/address.h"
#include "source/common/common/logger.h"
#include "envoy/config/core/v3/address.pb.h"
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Socks5ChannelCallbacks {
public:
  virtual ~Socks5ChannelCallbacks() = default;
  virtual void writeChannelData(bytes&& bytes) PURE;
};

class Socks5ClientHandshaker : public Logger::Loggable<Logger::Id::filter> {
public:
  Socks5ClientHandshaker(Socks5ChannelCallbacks& callbacks,
                         std::shared_ptr<const envoy::config::core::v3::Address> address);
  std::optional<Envoy::Network::Address::InstanceConstSharedPtr> result() const {
    return result_;
  }

  void startHandshake();
  absl::Status readChannelData(Buffer::Instance& buffer);

private:
  absl::Status decodeMethodSelection(Buffer::Instance& buffer);
  absl::Status decodeConnectResponse(Buffer::Instance& buffer);
  absl::Status sendConnectRequest();

  bool received_method_selection_{false};
  std::optional<Envoy::Network::Address::InstanceConstSharedPtr> result_;
  Socks5ChannelCallbacks& callbacks_;
  std::shared_ptr<const envoy::config::core::v3::Address> address_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
