#pragma once

#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/network/address.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network::Address {

class InternalStreamAddressImpl : public Instance {
public:
  InternalStreamAddressImpl(stream_id_t stream_id, std::shared_ptr<Network::SocketInterface> socket_interface)
      : stream_id_(stream_id),
        stream_address_(fmt::format("ssh:{}", stream_id)),
        fake_envoy_internal_addr_(stream_address_),
        socket_interface_(socket_interface) {}

  stream_id_t streamId() const { return stream_id_; }

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
  const std::string stream_address_;
  FakeEnvoyInternalAddress fake_envoy_internal_addr_;

  // This is initially created by an SshReverseTunnelCluster, and shared with all hosts in that
  // cluster. The concrete type is always InternalStreamSocketInterface.
  std::shared_ptr<Network::SocketInterface> socket_interface_;
};

using InternalStreamAddressConstSharedPtr = std::shared_ptr<const InternalStreamAddressImpl>;

} // namespace Envoy::Network::Address