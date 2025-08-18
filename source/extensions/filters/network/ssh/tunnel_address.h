#pragma once

#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/shared.h"
#include "source/extensions/filters/network/ssh/tunnel_address.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/network/socket_interface.h"
#include "absl/synchronization/notification.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network::Address {

using Extensions::NetworkFilters::GenericProxy::Codec::ActiveStreamTracker;
using Extensions::NetworkFilters::GenericProxy::Codec::ExternalChannel;

class FakeEnvoyInternalAddress : public EnvoyInternalAddress {
public:
  explicit FakeEnvoyInternalAddress(const std::string& stream_id_string)
      : stream_id_string_(stream_id_string) {}
  const std::string& addressId() const override {
    static auto id = "_ssh_internal_"s;
    return id;
  }
  const std::string& endpointId() const override {
    return stream_id_string_;
  }

private:
  std::string stream_id_string_;
};

class InternalStreamSocketInterface : public Network::SocketInterface {
public:
  InternalStreamSocketInterface(std::shared_ptr<ActiveStreamTracker> active_stream_tracker)
      : active_stream_tracker_(std::move(active_stream_tracker)) {
  }

  // SocketInterface
  Network::IoHandlePtr socket(Network::Socket::Type, Network::Address::Type, Network::Address::IpVersion,
                              bool, const Network::SocketCreationOptions&) const override {
    throw Envoy::EnvoyException("not implemented");
  }
  Network::IoHandlePtr socket(Network::Socket::Type socket_type,
                              const Network::Address::InstanceConstSharedPtr addr,
                              const Network::SocketCreationOptions& options) const override;
  bool ipFamilySupported(int) override { return true; }

private:
  mutable std::shared_ptr<ActiveStreamTracker> active_stream_tracker_;
};

class InternalStreamAddressImpl : public Instance {
public:
  InternalStreamAddressImpl(stream_id_t stream_id, std::shared_ptr<ActiveStreamTracker> active_stream_tracker)
      : stream_id_(stream_id),
        stream_id_string_(std::to_string(stream_id)),
        fake_envoy_internal_addr_(stream_id_string_),
        socket_interface_(std::move(active_stream_tracker)) {}

  stream_id_t streamId() const { return stream_id_; }

  bool operator==(const Instance&) const override { return false; }
  const std::string& asString() const override { return stream_id_string_; }
  absl::string_view asStringView() const override { return stream_id_string_; }
  const std::string& logicalName() const override { return stream_id_string_; }

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

  // NB: this selects our custom SshTunnelClientConnectionFactory when creating a connection for
  // this address
  absl::string_view addressType() const override {
    // return "default";
    return "ssh_tunnel";
  }

  const Network::SocketInterface& socketInterface() const override {
    return socket_interface_;
  }

  // XXX uncomment this when updating envoy
  // absl::optional<std::string> networkNamespace() const override { return absl::nullopt; }

private:
  const stream_id_t stream_id_;
  const std::string stream_id_string_;
  FakeEnvoyInternalAddress fake_envoy_internal_addr_;
  InternalStreamSocketInterface socket_interface_;
};

using InternalStreamAddressConstSharedPtr = std::shared_ptr<const InternalStreamAddressImpl>;

} // namespace Envoy::Network::Address