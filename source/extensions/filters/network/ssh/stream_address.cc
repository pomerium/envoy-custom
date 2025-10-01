#include "source/extensions/filters/network/ssh/stream_address.h"

namespace Envoy::Network::Address {

InternalStreamAddressImpl::InternalStreamAddressImpl(stream_id_t stream_id,
                                                     SshEndpointMetadataConstSharedPtr metadata,
                                                     std::shared_ptr<SocketInterfaceFactory> socket_interface_factory)
    : stream_id_(stream_id),
      stream_address_(fmt::format("ssh:{}", stream_id)),
      metadata_(metadata),
      fake_envoy_internal_addr_(stream_address_),
      socket_interface_factory_(socket_interface_factory) {}

InternalStreamAddressImpl::InternalStreamAddressImpl(const InternalStreamAddressConstSharedPtr& factory_address,
                                                     Event::Dispatcher& connection_dispatcher)
    : stream_id_(factory_address->stream_id_),
      stream_address_(factory_address->stream_address_),
      metadata_(factory_address->metadata_),
      fake_envoy_internal_addr_(factory_address->stream_address_),
      socket_interface_(factory_address->socketInterfaceFactory().createSocketInterface(connection_dispatcher)) {}

InternalStreamAddressImpl::~InternalStreamAddressImpl() = default;

std::shared_ptr<InternalStreamAddressImpl>
InternalStreamAddressImpl::createFromFactoryAddress(const InternalStreamAddressConstSharedPtr& factory_address,
                                                    Event::Dispatcher& connection_dispatcher) {
  return std::make_shared<InternalStreamAddressImpl>(factory_address, connection_dispatcher);
}

} // namespace Envoy::Network::Address