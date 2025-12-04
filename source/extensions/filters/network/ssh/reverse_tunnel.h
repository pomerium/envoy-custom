#pragma once

#include "source/extensions/filters/network/ssh/stream_address.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"

#pragma clang unsafe_buffer_usage begin
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "source/common/upstream/upstream_impl.h"
#pragma clang diagnostic pop
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
  COUNTER(downstream_flow_control_high_watermark_activated_total)                   \
  COUNTER(downstream_flow_control_low_watermark_activated_total)                    \
  STATNAME(ssh_reverse_tunnel)

MAKE_STAT_NAMES_STRUCT(ReverseTunnelStatNames, ALL_REVERSE_TUNNEL_STATS);
MAKE_STATS_STRUCT(ReverseTunnelStats, ReverseTunnelStatNames, ALL_REVERSE_TUNNEL_STATS);

namespace Network {

class HostDrainManager : NonCopyable {
public:
  Common::CallbackHandlePtr addHostDrainCallback(Event::Dispatcher& dispatcher, std::function<void()> cb) {
    return callbacks_->add(dispatcher, std::move(cb));
  }

protected:
  void runHostDrainCallbacks() {
    callbacks_->runCallbacks();
  }

private:
  std::shared_ptr<Common::ThreadSafeCallbackManager> callbacks_ =
    Common::ThreadSafeCallbackManager::create();
};

class ReverseTunnelClusterContext {
public:
  virtual ~ReverseTunnelClusterContext() = default;
  virtual const Upstream::ClusterInfoConstSharedPtr& clusterInfo() PURE;
  virtual const envoy::config::cluster::v3::Cluster& clusterConfig() PURE;
  virtual std::shared_ptr<StreamTracker> streamTracker() PURE;
  virtual std::shared_ptr<const envoy::config::core::v3::Address> chooseUpstreamAddress() PURE;
  virtual ReverseTunnelStats& reverseTunnelStats() PURE;
};

class HostContext {
public:
  virtual ~HostContext() = default;

  virtual const pomerium::extensions::ssh::EndpointMetadata& hostMetadata() PURE;
  virtual HostDrainManager& hostDrainManager() PURE;
  virtual ReverseTunnelClusterContext& clusterContext() PURE;
};

} // namespace Network

namespace Upstream {

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
  // SOTW update
  absl::Status onConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                              const std::string& version_info) override;

  // Delta update
  absl::Status onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& version_info) override;

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
  Event::Dispatcher& dispatcher_;
  Config::SubscriptionPtr eds_subscription_;
  std::unique_ptr<Network::ReverseTunnelClusterContext> owned_context_;
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

inline Envoy::Thread::ThreadSynchronizer remote_stream_handler_sync;
