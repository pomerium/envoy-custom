#include "source/extensions/filters/network/ssh/stream_address.h"

namespace Envoy::Network::Address {

InternalStreamAddressImpl::InternalStreamAddressImpl(InternalStreamContext& context,
                                                     std::shared_ptr<SocketInterfaceFactory> socket_interface_factory)
    : context_(context),
      fake_envoy_internal_addr_(context_.streamAddress()),
      socket_interface_factory_(socket_interface_factory) {}

InternalStreamAddressImpl::InternalStreamAddressImpl(const InternalStreamAddressConstSharedPtr& factory_address,
                                                     Event::Dispatcher& connection_dispatcher)
    : context_(factory_address->context_),
      fake_envoy_internal_addr_(context_.streamAddress()),
      socket_interface_(factory_address->socketInterfaceFactory().createSocketInterface(connection_dispatcher)) {}

InternalStreamAddressImpl::~InternalStreamAddressImpl() = default;

std::shared_ptr<InternalStreamAddressImpl>
InternalStreamAddressImpl::createFromFactoryAddress(const InternalStreamAddressConstSharedPtr& factory_address,
                                                    Event::Dispatcher& connection_dispatcher) {
  return std::make_shared<InternalStreamAddressImpl>(factory_address, connection_dispatcher);
}

} // namespace Envoy::Network::Address