#pragma once

#include "source/extensions/filters/network/ssh/common.h"
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
namespace clusterv3 = envoy::config::cluster::v3;
namespace endpointv3 = envoy::config::endpoint::v3;

namespace Envoy::Upstream {

class SshReverseTunnelCluster : public ClusterImplBase,
                                public Envoy::Config::SubscriptionBase<endpointv3::ClusterLoadAssignment>,
                                public std::enable_shared_from_this<SshReverseTunnelCluster> {
public:
  static absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
  create(const clusterv3::Cluster& cluster,
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

  absl::StatusOr<HostSharedPtr> newHostForStreamId(stream_id_t id);

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
  std::shared_ptr<Network::SocketInterface> socket_interface_;
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

} // namespace Envoy::Upstream