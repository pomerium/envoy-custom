#pragma once

#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/network/address.h"
#include "envoy/event/dispatcher.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network::Address {

class SocketInterfaceFactory {
public:
  virtual ~SocketInterfaceFactory() = default;
  virtual std::unique_ptr<Network::SocketInterface> createSocketInterface(Event::Dispatcher& connection_dispatcher) PURE;
};

class InternalStreamAddressImpl : public Instance {
public:
  InternalStreamAddressImpl(stream_id_t stream_id, uint32_t port, bool is_dynamic, std::shared_ptr<SocketInterfaceFactory> socket_interface_factory);
  InternalStreamAddressImpl(stream_id_t stream_id, uint32_t port, bool is_dynamic, std::unique_ptr<Network::SocketInterface> socket_interface);
  ~InternalStreamAddressImpl();

  stream_id_t streamId() const { return stream_id_; }
  uint32_t virtualPort() const { return port_; }
  bool isDynamic() const { return is_dynamic_; }

  bool operator==(const Instance&) const override { return false; }
  const std::string& asString() const override { return stream_address_; }
  absl::string_view asStringView() const override { return stream_address_; }
  const std::string& logicalName() const override { return stream_address_; }

  const Ip* ip() const override { return nullptr; }
  const Pipe* pipe() const override { return nullptr; }
  const EnvoyInternalAddress* envoyInternalAddress() const override {
    // this is only used for access logs, but needs to be non-nil
    return &fake_envoy_internal_addr_;
  }

  const sockaddr* sockAddr() const override { return nullptr; }
  socklen_t sockAddrLen() const override { return 0; }

  Type type() const override {
    // TODO(kralicky): none of these really work but EnvoyInternal seems to avoid creating a socket
    return Type::EnvoyInternal;
  }

  // NB: this selects our custom connection factory when creating a connection for this address
  absl::string_view addressType() const override { return "ssh_tunnel"; }

  const Network::SocketInterface& socketInterface() const override {
    return *socket_interface_;
  }
  SocketInterfaceFactory& socketInterfaceFactory() const {
    return *socket_interface_factory_;
  }

  // XXX uncomment this when updating envoy
  // absl::optional<std::string> networkNamespace() const override { return absl::nullopt; }

  class FakeEnvoyInternalAddress : public EnvoyInternalAddress {
  public:
    explicit FakeEnvoyInternalAddress(const std::string& address_id)
        : address_id_(address_id) {}
    const std::string& addressId() const override { return address_id_; }
    const std::string& endpointId() const override { return endpoint_id_; }

  private:
    const std::string address_id_;
    const std::string endpoint_id_;
  };

private:
  const stream_id_t stream_id_;
  const uint32_t port_;
  const bool is_dynamic_;
  const std::string stream_address_;
  FakeEnvoyInternalAddress fake_envoy_internal_addr_;

  // This is initially created by an SshReverseTunnelCluster, and shared with all hosts in that
  // cluster. The concrete type is always InternalStreamSocketInterfaceFactory.
  std::shared_ptr<SocketInterfaceFactory> socket_interface_factory_;
  std::unique_ptr<Network::SocketInterface> socket_interface_;
};

using InternalStreamAddressConstSharedPtr = std::shared_ptr<const InternalStreamAddressImpl>;

} // namespace Envoy::Network::Address