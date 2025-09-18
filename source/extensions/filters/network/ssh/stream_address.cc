#include "source/extensions/filters/network/ssh/stream_address.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/network/socket_interface.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network::Address {

InternalStreamAddressImpl::InternalStreamAddressImpl(stream_id_t stream_id, uint32_t port, bool is_dynamic, std::shared_ptr<SocketInterfaceFactory> socket_interface_factory)
    : stream_id_(stream_id),
      port_(port),
      is_dynamic_(is_dynamic),
      stream_address_(fmt::format("ssh:{}", stream_id)),
      fake_envoy_internal_addr_(stream_address_),
      socket_interface_factory_(socket_interface_factory) {}

InternalStreamAddressImpl::InternalStreamAddressImpl(stream_id_t stream_id, uint32_t port, bool is_dynamic, std::unique_ptr<Network::SocketInterface> socket_interface)
    : stream_id_(stream_id),
      port_(port),
      is_dynamic_(is_dynamic),
      stream_address_(fmt::format("ssh:{}", stream_id)),
      fake_envoy_internal_addr_(stream_address_),
      socket_interface_(std::move(socket_interface)) {}

InternalStreamAddressImpl::~InternalStreamAddressImpl() = default;

} // namespace Envoy::Network::Address