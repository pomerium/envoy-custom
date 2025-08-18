#pragma once

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
#pragma clang unsafe_buffer_usage end

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ActiveStreamEndpointListener;

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
         Server::Configuration::ServerFactoryContext& server_context);

  stream_id_t streamId() const { return id_; }

protected:
  InternalStreamHost(absl::Status& creation_status,
                     stream_id_t id,
                     const envoy::config::cluster::v3::Cluster& cluster,
                     Server::Configuration::ServerFactoryContext& server_context);

  stream_id_t id_;
};

class SshReverseTunnelCluster : public ClusterImplBase,
                                public ActiveStreamEndpointListener,
                                public std::enable_shared_from_this<SshReverseTunnelCluster> {
public:
  static absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
  create(const envoy::config::cluster::v3::Cluster& cluster,
         const pomerium::extensions::ssh::UpstreamCluster& proto_config,
         ClusterFactoryContext& cluster_context);

  InitializePhase initializePhase() const override { return Cluster::InitializePhase::Primary; }

  void startPreInit() override;

  void onClusterEndpointAdded(stream_id_t key) override {
    dispatcher_.post([this, key] {
      auto newHost = *newHostForStreamId(key); // XXX
      const auto& hostSet = priority_set_.getOrCreateHostSet(0);
      HostVectorSharedPtr all_hosts(new HostVector(hostSet.hosts()));
      all_hosts->emplace_back(newHost);
      priority_set_.updateHosts(0, HostSetImpl::partitionHosts(all_hosts, HostsPerLocalityImpl::empty()), {}, {std::move(newHost)}, {},
                                server_context_.api().randomGenerator().random(),
                                std::nullopt, std::nullopt);
    });
  }

  void onClusterEndpointRemoved(stream_id_t key) override {
    dispatcher_.post([this, key] {
      const auto& hostSet = priority_set_.getOrCreateHostSet(0);
      HostVectorSharedPtr all_hosts(new HostVector(hostSet.hosts()));

      HostSharedPtr toRemove;
      for (auto it = all_hosts->begin(); it != all_hosts->end(); it++) {
        if (static_cast<InternalStreamHost&>(**it).streamId() == key) {
          toRemove = *it;
          all_hosts->erase(it);
          break;
        }
      }
      ASSERT(toRemove != nullptr);
      priority_set_.updateHosts(0, HostSetImpl::partitionHosts(all_hosts, HostsPerLocalityImpl::empty()), {}, {}, {toRemove},
                                server_context_.api().randomGenerator().random(),
                                false, std::nullopt);
    });
  }

protected:
  // NB: ClusterFactoryContext is short-lived, it cannot be stored as a member here
  SshReverseTunnelCluster(const envoy::config::cluster::v3::Cluster& cluster,
                          const pomerium::extensions::ssh::UpstreamCluster& proto_config,
                          ClusterFactoryContext& cluster_context,
                          absl::Status& creation_status);

  absl::StatusOr<HostSharedPtr> newHostForStreamId(stream_id_t id) {
    return InternalStreamHost::create(id, cluster_, server_context_);
  }

private:
  envoy::config::cluster::v3::Cluster cluster_;
  Server::Configuration::ServerFactoryContext& server_context_;
  pomerium::extensions::ssh::UpstreamCluster config_;
  std::shared_ptr<Extensions::NetworkFilters::GenericProxy::Codec::ActiveStreamTracker> active_stream_tracker_;
  Event::Dispatcher& dispatcher_;
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
