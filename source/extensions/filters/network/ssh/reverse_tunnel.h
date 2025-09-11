#pragma once

#include "source/extensions/filters/network/ssh/stream_address.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"

#pragma clang unsafe_buffer_usage begin
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "source/common/upstream/upstream_impl.h"
#pragma clang diagnostic pop
#include "source/extensions/io_socket/user_space/io_handle_impl.h"
#include "envoy/registry/registry.h"
#include "source/common/upstream/cluster_factory_impl.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
#pragma clang unsafe_buffer_usage end

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::StreamTracker;

namespace Envoy {
#define ALL_REVERSE_TUNNEL_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME) \
  COUNTER(upstream_flow_control_window_adjustment_paused_total)                     \
  COUNTER(upstream_flow_control_window_adjustment_resumed_total)                    \
  COUNTER(upstream_flow_control_local_window_exhausted_total)                       \
  COUNTER(upstream_flow_control_local_window_restored_total)                        \
  COUNTER(downstream_flow_control_remote_window_exhausted_total)                    \
  COUNTER(downstream_flow_control_remote_window_restored_total)                     \
  STATNAME(reverse_tunnel)

MAKE_STAT_NAMES_STRUCT(ReverseTunnelStatNames, ALL_REVERSE_TUNNEL_STATS);
MAKE_STATS_STRUCT(ReverseTunnelStats, ReverseTunnelStatNames, ALL_REVERSE_TUNNEL_STATS);

namespace Network {

class InternalStreamPassthroughState : public Envoy::Extensions::IoSocket::UserSpace::PassthroughStateImpl {
public:
  using enum PassthroughStateImpl::State;

  void initialize(std::unique_ptr<envoy::config::core::v3::Metadata> metadata,
                  const StreamInfo::FilterState::Objects& filter_state_objects) override {
    ASSERT(state_ == State::Created);
    PassthroughStateImpl::initialize(std::move(metadata), filter_state_objects);
    ASSERT(state_ == State::Initialized);
    if (init_callback_ == nullptr) {
      return;
    }
    std::exchange(init_callback_, nullptr)();
  }

  void setOnInitializedCallback(absl::AnyInvocable<void()> callback) {
    ASSERT(init_callback_ == nullptr && state_ < State::Done);
    if (state_ == State::Created) {
      init_callback_ = std::move(callback);
      return;
    }
    callback();
  }

  bool isInitialized() const {
    return state_ == State::Initialized;
  }

  static std::shared_ptr<InternalStreamPassthroughState> fromIoHandle(IoHandle& io_handle) {
    return std::dynamic_pointer_cast<InternalStreamPassthroughState>(
      dynamic_cast<Extensions::IoSocket::UserSpace::IoHandleImpl&>(io_handle).passthroughState());
  }

private:
  absl::AnyInvocable<void()> init_callback_;
};

} // namespace Network

namespace Upstream {

class InternalStreamSocketInterfaceFactory : public Network::Address::SocketInterfaceFactory {
public:
  InternalStreamSocketInterfaceFactory(std::shared_ptr<StreamTracker> stream_tracker,
                                       const envoy::config::endpoint::v3::ClusterLoadAssignment& load_assignment,
                                       ReverseTunnelStats& reverse_tunnel_stats);
  virtual ~InternalStreamSocketInterfaceFactory() = default;

  std::unique_ptr<Network::SocketInterface> createSocketInterface(Event::Dispatcher& connection_dispatcher) override;

private:
  std::shared_ptr<StreamTracker> stream_tracker_;
  std::vector<std::shared_ptr<const envoy::config::core::v3::Address>> upstream_addresses_;
  ReverseTunnelStats& reverse_tunnel_stats_; // owned by the cluster
};

class SshReverseTunnelCluster : public ClusterImplBase,
                                public Envoy::Config::SubscriptionBase<envoy::config::endpoint::v3::ClusterLoadAssignment>,
                                public std::enable_shared_from_this<SshReverseTunnelCluster> {
public:
  static absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
  create(const envoy::config::cluster::v3::Cluster& cluster,
         const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
         ClusterFactoryContext& cluster_context);

  // ClusterImplBase
  InitializePhase initializePhase() const override { return Cluster::InitializePhase::Primary; }
  void startPreInit() override;

  // SubscriptionBase
  absl::Status onConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                              const std::string&) override;

  absl::Status onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>&,
                              const std::string&) override;

  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason reason, const EnvoyException*) override;

protected:
  // NB: ClusterFactoryContext is short-lived, it cannot be stored as a member here
  SshReverseTunnelCluster(const envoy::config::cluster::v3::Cluster& cluster,
                          const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                          const envoy::config::endpoint::v3::ClusterLoadAssignment& load_assignment,
                          ClusterFactoryContext& cluster_context,
                          absl::Status& creation_status);

private:
  absl::Status update(const envoy::config::endpoint::v3::ClusterLoadAssignment& cluster_load_assignment);

  const std::string& edsServiceName() const {
    const std::string& name = info_->edsServiceName();
    return !name.empty() ? name : info_->name();
  }

  envoy::config::cluster::v3::Cluster cluster_;
  Server::Configuration::ServerFactoryContext& server_context_;
  pomerium::extensions::ssh::ReverseTunnelCluster config_;
  std::shared_ptr<StreamTracker> stream_tracker_;
  ReverseTunnelStatNames reverse_tunnel_stat_names_;
  ReverseTunnelStats reverse_tunnel_stats_;
  std::shared_ptr<InternalStreamSocketInterfaceFactory> socket_interface_factory_;
  Event::Dispatcher& dispatcher_;
  Config::SubscriptionPtr eds_subscription_;
};

class SshReverseTunnelClusterFactory : public ConfigurableClusterFactoryBase<pomerium::extensions::ssh::ReverseTunnelCluster> {
public:
  SshReverseTunnelClusterFactory();

private:
  absl::StatusOr<std::pair<Upstream::ClusterImplBaseSharedPtr, Upstream::ThreadAwareLoadBalancerPtr>>
  createClusterWithConfig(
    const envoy::config::cluster::v3::Cluster& cluster,
    const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
    Upstream::ClusterFactoryContext& context) override;
};

DECLARE_FACTORY(SshReverseTunnelClusterFactory);

} // namespace Upstream
} // namespace Envoy