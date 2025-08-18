#include "source/extensions/filters/network/ssh/tunnel_address.h"
#include "source/common/status.h"

namespace Envoy::Network::Address {

Network::IoHandlePtr InternalStreamSocketInterface::socket(Network::Socket::Type socket_type,
                                                           const Network::Address::InstanceConstSharedPtr addr,
                                                           [[maybe_unused]] const Network::SocketCreationOptions& options) const {
  ASSERT(socket_type == Network::Socket::Type::Stream);
  auto [local, remote] = Extensions::IoSocket::UserSpace::IoHandleFactory::createIoHandlePair();

  auto r = active_stream_tracker_->requestOpenDownstreamChannel(addr, std::move(local));
  if (!r.ok()) {
    ENVOY_LOG_MISC(error, "error requesting channel: {}", statusToString(r));
    return nullptr;
  }
  return std::move(remote);
}
} // namespace Envoy::Network::Address