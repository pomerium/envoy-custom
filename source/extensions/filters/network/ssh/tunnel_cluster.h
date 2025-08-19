#pragma once

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/shared.h"

#pragma clang unsafe_buffer_usage begin

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "source/common/upstream/upstream_impl.h"
#pragma clang diagnostic pop
#include "source/common/upstream/cluster_factory_impl.h"
#include "envoy/registry/registry.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.validate.h"
#pragma clang unsafe_buffer_usage end

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ActiveStreamTracker;
namespace clusterv3 = envoy::config::cluster::v3;
namespace endpointv3 = envoy::config::endpoint::v3;

namespace Envoy::Upstream {

// Copy of ProdClusterInfoFactory, but with Stats::Store param replaced with Stats::Scope.
// It is (as far as I can tell) impossible to get a Stats::Store instance here.
namespace detail {
struct CreateClusterInfoParams {
  Server::Configuration::ServerFactoryContext& server_context_;
  const envoy::config::cluster::v3::Cluster& cluster_;
  const envoy::config::core::v3::BindConfig& bind_config_;
  Stats::Scope& scope_;
  const bool added_via_api_;
};

inline ClusterInfoConstSharedPtr createClusterInfo(CreateClusterInfoParams params) {
  Envoy::Stats::ScopeSharedPtr scope =
    params.scope_.createScope(fmt::format("cluster.{}.", params.cluster_.name()));

  Envoy::Server::Configuration::TransportSocketFactoryContextImpl factory_context(
    params.server_context_, *scope, params.server_context_.messageValidationVisitor());

  // TODO(JimmyCYJ): Support SDS for HDS cluster.
  Network::UpstreamTransportSocketFactoryPtr socket_factory = THROW_OR_RETURN_VALUE(
    Upstream::createTransportSocketFactory(params.cluster_, factory_context),
    Network::UpstreamTransportSocketFactoryPtr);
  auto socket_matcher = THROW_OR_RETURN_VALUE(
    TransportSocketMatcherImpl::create(params.cluster_.transport_socket_matches(),
                                       factory_context, socket_factory, *scope),
    std::unique_ptr<TransportSocketMatcherImpl>);

  return THROW_OR_RETURN_VALUE(
    ClusterInfoImpl::create(params.server_context_.initManager(), params.server_context_,
                            params.cluster_, params.bind_config_,
                            params.server_context_.runtime(), std::move(socket_matcher),
                            std::move(scope), params.added_via_api_, factory_context),
    std::unique_ptr<ClusterInfoImpl>);
}
} // namespace detail
/////

class InternalStreamHost : public HostImpl {
public:
  static absl::StatusOr<HostSharedPtr>
  create(stream_id_t id,
         const envoy::config::cluster::v3::Cluster& cluster,
         Server::Configuration::ServerFactoryContext& server_context,
         std::shared_ptr<ActiveStreamTracker> active_stream_tracker);

  stream_id_t streamId() const { return id_; }

protected:
  InternalStreamHost(absl::Status& creation_status,
                     stream_id_t id,
                     const envoy::config::cluster::v3::Cluster& cluster,
                     Server::Configuration::ServerFactoryContext& server_context,
                     std::shared_ptr<ActiveStreamTracker> active_stream_tracker);

  stream_id_t id_;
};

class SshReverseTunnelCluster : public ClusterImplBase,
                                public Envoy::Config::SubscriptionBase<endpointv3::ClusterLoadAssignment>,
                                public std::enable_shared_from_this<SshReverseTunnelCluster> {
public:
  static absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
  create(const clusterv3::Cluster& cluster,
         const pomerium::extensions::ssh::UpstreamCluster& proto_config,
         ClusterFactoryContext& cluster_context);

  // ClusterImplBase
  InitializePhase initializePhase() const override { return Cluster::InitializePhase::Primary; }
  void startPreInit() override;

  // SubscriptionBase
  absl::Status onConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                              const std::string&) override {
    if (resources.empty()) {
      ENVOY_LOG(info, "Missing ClusterLoadAssignment for {} in onConfigUpdate()", edsServiceName());
      info_->configUpdateStats().update_empty_.inc();
      return absl::OkStatus();
    }
    if (resources.size() != 1) {
      return absl::InvalidArgumentError(
        fmt::format("Unexpected EDS resource length: {}", resources.size()));
    }
    ENVOY_LOG(info, "received EDS update for cluster {}", edsServiceName());
    const auto& cluster_load_assignment =
      dynamic_cast<const endpointv3::ClusterLoadAssignment&>(resources[0].get().resource());
    if (cluster_load_assignment.cluster_name() != edsServiceName()) {
      return absl::InvalidArgumentError(fmt::format("Unexpected EDS cluster (expecting {}): {}",
                                                    edsServiceName(),
                                                    cluster_load_assignment.cluster_name()));
    }

    // TODO: handle endpoint_stale_after

    return update(cluster_load_assignment);
  }

  absl::Status onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>&,
                              const std::string&) override {
    return onConfigUpdate(added_resources, "");
  }

  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason reason, const EnvoyException*) override {
    switch (reason) {
    case Config::ConfigUpdateFailureReason::ConnectionFailure:
      ENVOY_LOG(error, "onConfigUpdateFailed for cluster {}: connection failure ", edsServiceName());
      break;
    case Config::ConfigUpdateFailureReason::FetchTimedout:
      ENVOY_LOG(error, "onConfigUpdateFailed for cluster {}: fetch timeout", edsServiceName());
      break;
    case Config::ConfigUpdateFailureReason::UpdateRejected:
      ENVOY_LOG(error, "onConfigUpdateFailed for cluster {}: update rejected", edsServiceName());
      break;
    }
    // TODO: handle this
    // update({}).IgnoreError();
  }

protected:
  // NB: ClusterFactoryContext is short-lived, it cannot be stored as a member here
  SshReverseTunnelCluster(const envoy::config::cluster::v3::Cluster& cluster,
                          const pomerium::extensions::ssh::UpstreamCluster& proto_config,
                          ClusterFactoryContext& cluster_context,
                          absl::Status& creation_status);

  absl::StatusOr<HostSharedPtr> newHostForStreamId(stream_id_t id) {
    return InternalStreamHost::create(id, cluster_, server_context_, active_stream_tracker_);
  }

private:
  absl::Status update(const envoy::config::endpoint::v3::ClusterLoadAssignment& cluster_load_assignment) {
    // only using one priority here (0)
    constexpr uint32_t priority = 0;
    const auto& hostSet = priority_set_.getOrCreateHostSet(priority).hosts();

    const auto& hostMap = priority_set_.crossPriorityHostMap();
    std::unordered_set<std::string> updatedEndpoints{};
    for (const auto& locality_lb_endpoint : cluster_load_assignment.endpoints()) {
      for (const auto& lb_endpoint : locality_lb_endpoint.lb_endpoints()) {
        updatedEndpoints.insert(lb_endpoint.endpoint_name());
      }
    }

    HostVector hostsToAdd;
    HostVector hostsToRemove;
    for (const auto& [key, value] : *hostMap) {
      if (!updatedEndpoints.contains(key)) {
        hostsToRemove.push_back(value);
      }
    }
    for (const auto& endpointName : updatedEndpoints) {
      auto endpointNameView = std::string_view(endpointName);
      if (!hostMap->contains(endpointNameView)) {
        constexpr auto prefix = "ssh:"sv;
        if (!endpointNameView.starts_with(prefix)) {
          return absl::InternalError("invalid lb endpoint name '{}' (expecting format 'ssh:<id>')");
        }
        endpointNameView.remove_prefix(prefix.size());
        stream_id_t streamId{};
        if (!absl::SimpleAtoi(endpointNameView, &streamId)) {
          return absl::InternalError("bug: invalid lb endpoint name (expecting stream ID)");
        }

        auto newHost = newHostForStreamId(streamId);
        if (!newHost.ok()) {
          return statusf("failed to create host for stream ID: {}", newHost.status());
        }
        hostsToAdd.push_back(std::move(newHost).value());
      }
    }

    HostVectorSharedPtr filteredHostSetCopy(new HostVector());
    // copy all the existing hosts, except those that have been removed
    std::copy_if(hostSet.begin(), hostSet.end(), std::back_inserter(*filteredHostSetCopy),
                 [&](const HostSharedPtr& host) {
                   return !std::ranges::contains(hostsToRemove, host);
                 });
    // copy all the new hosts
    std::copy(hostsToAdd.begin(), hostsToAdd.end(), std::back_inserter(*filteredHostSetCopy));

    ENVOY_LOG(info, "updating endpoints for cluster {}: {} added, {} removed, {} total", edsServiceName(),
              hostsToAdd.size(), hostsToRemove.size(), filteredHostSetCopy->size());
    priority_set_.updateHosts(priority,
                              HostSetImpl::partitionHosts(filteredHostSetCopy, HostsPerLocalityImpl::empty()), {},
                              std::move(hostsToAdd),
                              std::move(hostsToRemove),
                              server_context_.api().randomGenerator().random(),
                              std::nullopt, std::nullopt);

    onPreInitComplete(); // the first valid update will complete cluster initialization
    return absl::OkStatus();
  }

  const std::string& edsServiceName() const {
    const std::string& name = info_->edsServiceName();
    return !name.empty() ? name : info_->name();
  }

  envoy::config::cluster::v3::Cluster cluster_;
  Server::Configuration::ServerFactoryContext& server_context_;
  pomerium::extensions::ssh::UpstreamCluster config_;
  std::shared_ptr<ActiveStreamTracker> active_stream_tracker_;
  Event::Dispatcher& dispatcher_;
  Config::SubscriptionPtr eds_subscription_;
};

class SshReverseTunnelClusterFactory : public ConfigurableClusterFactoryBase<pomerium::extensions::ssh::UpstreamCluster> {
public:
  SshReverseTunnelClusterFactory() : ConfigurableClusterFactoryBase("envoy.clusters.ssh_reverse_tunnel") {}

private:
  absl::StatusOr<std::pair<Upstream::ClusterImplBaseSharedPtr, Upstream::ThreadAwareLoadBalancerPtr>>
  createClusterWithConfig(
    const envoy::config::cluster::v3::Cluster& cluster,
    const pomerium::extensions::ssh::UpstreamCluster& proto_config,
    Upstream::ClusterFactoryContext& context) override {
    return std::make_pair(*SshReverseTunnelCluster::create(cluster, proto_config, context), nullptr);
  }
};

DECLARE_FACTORY(SshReverseTunnelClusterFactory);

} // namespace Envoy::Upstream
