#include "source/extensions/filters/network/ssh/tunnel_connection_factory.h"

#include "source/extensions/filters/network/ssh/filter_state_objects.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/network/connection_impl.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network {

Network::ClientConnectionPtr SshTunnelClientConnectionFactory::createClientConnection(
  Event::Dispatcher& dispatcher, Network::Address::InstanceConstSharedPtr address,
  Network::Address::InstanceConstSharedPtr source_address,
  Network::TransportSocketPtr&& transport_socket,
  const Network::ConnectionSocket::OptionsSharedPtr& options,
  const Network::TransportSocketOptionsConstSharedPtr& transport_options) {
  ENVOY_LOG(info, "SshTunnelClientConnectionFactory::createClientConnection");
  return std::make_unique<Network::ClientConnectionImpl>(
    dispatcher, address, source_address, std::move(transport_socket), options, transport_options);
}
REGISTER_FACTORY(SshTunnelClientConnectionFactory, Network::ClientConnectionFactory);

} // namespace Envoy::Network