#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/network/client_connection_factory.h"
#include "envoy/network/connection.h"
#include "envoy/registry/registry.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network {

// This is only required to avoid an ASSERT in the default client connection factory which doesn't
// apply to the internal ssh tunnel connections.
class SshTunnelClientConnectionFactory : public ClientConnectionFactory,
                                         public Logger::Loggable<Logger::Id::connection> {
public:
  ~SshTunnelClientConnectionFactory() override = default;

  // Config::UntypedFactory
  std::string name() const override { return "ssh_tunnel"; }

  // Network::ClientConnectionFactory
  Network::ClientConnectionPtr createClientConnection(
    Event::Dispatcher& dispatcher, Network::Address::InstanceConstSharedPtr address,
    Network::Address::InstanceConstSharedPtr source_address,
    Network::TransportSocketPtr&& transport_socket,
    const Network::ConnectionSocket::OptionsSharedPtr& options,
    const Network::TransportSocketOptionsConstSharedPtr& transport_options) override;
};

DECLARE_FACTORY(DefaultClientConnectionFactory);

} // namespace Envoy::Network