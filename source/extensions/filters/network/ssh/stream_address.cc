#include "source/extensions/filters/network/ssh/stream_address.h"

namespace Envoy::Network::Address {

SshStreamAddress::SshStreamAddress(stream_id_t stream_id,
                                   HostContext& context,
                                   std::shared_ptr<SshSocketInterfaceFactory> socket_interface_factory)
    : stream_id_(stream_id),
      stream_address_(fmt::format("ssh:{}", stream_id)),
      context_(context),
      fake_envoy_internal_addr_(stream_address_),
      socket_interface_factory_(socket_interface_factory) {}

SshStreamAddress::SshStreamAddress(const SshStreamAddressConstSharedPtr& factory_address,
                                   Event::Dispatcher& connection_dispatcher)
    : stream_id_(factory_address->stream_id_),
      stream_address_(factory_address->stream_address_),
      context_(factory_address->context_),
      fake_envoy_internal_addr_(factory_address->stream_address_),
      socket_interface_(factory_address->socketInterfaceFactory().createSocketInterface(connection_dispatcher)) {}

SshStreamAddress::~SshStreamAddress() = default;

std::shared_ptr<SshStreamAddress>
SshStreamAddress::createFromFactoryAddress(const SshStreamAddressConstSharedPtr& factory_address,
                                           Event::Dispatcher& connection_dispatcher) {
  return std::make_shared<SshStreamAddress>(factory_address, connection_dispatcher);
}

} // namespace Envoy::Network::Address