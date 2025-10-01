#pragma once

#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/network/socket_interface.h"
#include "envoy/event/dispatcher.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network::Address {

using SshEndpointMetadataConstSharedPtr = std::shared_ptr<const pomerium::extensions::ssh::EndpointMetadata>;

class SocketInterfaceFactory {
public:
  virtual ~SocketInterfaceFactory() = default;
  virtual Network::SocketInterfacePtr createSocketInterface(Event::Dispatcher& connection_dispatcher) PURE;
};

class InternalStreamAddressImpl : public Instance {
public:
  InternalStreamAddressImpl(stream_id_t stream_id,
                            SshEndpointMetadataConstSharedPtr metadata,
                            std::shared_ptr<SocketInterfaceFactory> socket_interface_factory);
  InternalStreamAddressImpl(const std::shared_ptr<const InternalStreamAddressImpl>& factory_address,
                            Event::Dispatcher& connection_dispatcher);
  ~InternalStreamAddressImpl();

  static std::shared_ptr<InternalStreamAddressImpl>
  createFromFactoryAddress(const std::shared_ptr<const InternalStreamAddressImpl>& factory_address,
                           Event::Dispatcher& connection_dispatcher);

  stream_id_t streamId() const { return stream_id_; }
  const SshEndpointMetadataConstSharedPtr& endpointMetadata() const { return metadata_; }

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
  absl::string_view addressType() const override { return "ssh_stream"; }

  const Network::SocketInterface& socketInterface() const override {
    ASSERT(socket_interface_ != nullptr);
    return *socket_interface_;
  }
  SocketInterfaceFactory& socketInterfaceFactory() const {
    ASSERT(socket_interface_factory_ != nullptr);
    return *socket_interface_factory_;
  }

  std::optional<std::string> networkNamespace() const override { return std::nullopt; }

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
  const std::string stream_address_;
  SshEndpointMetadataConstSharedPtr metadata_;
  FakeEnvoyInternalAddress fake_envoy_internal_addr_;

  // This is initially created by an SshReverseTunnelCluster, and shared with all hosts in that
  // cluster. The concrete type is always InternalStreamSocketInterfaceFactory.
  std::shared_ptr<SocketInterfaceFactory> socket_interface_factory_;
  Network::SocketInterfacePtr socket_interface_;
};

using InternalStreamAddressConstSharedPtr = std::shared_ptr<const InternalStreamAddressImpl>;

} // namespace Envoy::Network::Address