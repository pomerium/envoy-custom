#include "source/extensions/filters/network/ssh/tunnel_cluster.h"
#include "source/extensions/filters/network/ssh/tunnel_address.h"

namespace Envoy::Upstream {

absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
SshReverseTunnelCluster::create(const envoy::config::cluster::v3::Cluster& cluster,
                                const pomerium::extensions::ssh::UpstreamCluster& proto_config,
                                ClusterFactoryContext& cluster_context) {
  absl::Status creation_status = absl::OkStatus();
  std::unique_ptr<SshReverseTunnelCluster> ret =
    absl::WrapUnique(new SshReverseTunnelCluster(cluster, proto_config, cluster_context, creation_status));
  RETURN_IF_NOT_OK(creation_status);
  return ret;
}

SshReverseTunnelCluster::SshReverseTunnelCluster(const envoy::config::cluster::v3::Cluster& cluster,
                                                 const pomerium::extensions::ssh::UpstreamCluster& proto_config,
                                                 ClusterFactoryContext& cluster_context,
                                                 absl::Status& creation_status)
    : ClusterImplBase(cluster, cluster_context, creation_status),
      Envoy::Config::SubscriptionBase<envoy::config::endpoint::v3::ClusterLoadAssignment>(
        cluster_context.messageValidationVisitor(), "cluster_name"),
      cluster_(cluster),
      server_context_(cluster_context.serverFactoryContext()),
      config_(proto_config),
      active_stream_tracker_(ActiveStreamTracker::fromContext(cluster_context.serverFactoryContext())),
      dispatcher_(cluster_context.serverFactoryContext().mainThreadDispatcher()) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  RETURN_ONLY_IF_NOT_OK_REF(creation_status);

  auto stat =
    cluster_context
      .clusterManager()
      .subscriptionFactory()
      .subscriptionFromConfigSource(proto_config.eds_config(),
                                    "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
                                    info_->statsScope(), *this, resource_decoder_, {});
  SET_AND_RETURN_IF_NOT_OK(stat.status(), creation_status);
  eds_subscription_ = std::move(stat).value();
}

void SshReverseTunnelCluster::startPreInit() {
  ENVOY_LOG(info, "starting EDS subscription (cluster={})", cluster_.name());
  eds_subscription_->start({info_->name()});
}

REGISTER_FACTORY(SshReverseTunnelClusterFactory, ClusterFactory);

absl::StatusOr<HostSharedPtr>
InternalStreamHost::create(stream_id_t id,
                           const envoy::config::cluster::v3::Cluster& cluster,
                           Server::Configuration::ServerFactoryContext& server_context,
                           std::shared_ptr<ActiveStreamTracker> active_stream_tracker) {
  absl::Status creation_status = absl::OkStatus();
  auto ret = std::shared_ptr<InternalStreamHost>(new InternalStreamHost(creation_status, id, cluster, server_context, std::move(active_stream_tracker)));
  RETURN_IF_NOT_OK(creation_status);
  return ret;
}

InternalStreamHost::InternalStreamHost(absl::Status& creation_status,
                                       stream_id_t stream_id,
                                       const envoy::config::cluster::v3::Cluster& cluster,
                                       Server::Configuration::ServerFactoryContext& server_context,
                                       std::shared_ptr<ActiveStreamTracker> active_stream_tracker)
    : HostImpl(creation_status,
               detail::createClusterInfo({
                 .server_context_ = server_context,
                 .cluster_ = cluster,
                 .bind_config_ = *server_context.clusterManager().bindConfig(),
                 .scope_ = server_context.scope(),
                 .added_via_api_ = true,
               }),
               fmt::format("ssh:{}", stream_id),
               std::make_shared<Network::Address::InternalStreamAddressImpl>(stream_id, active_stream_tracker), nullptr, nullptr, 1,
               envoy::config::core::v3::Locality().default_instance(),
               envoy::config::endpoint::v3::Endpoint::HealthCheckConfig().default_instance(),
               0, envoy::config::core::v3::HEALTHY, server_context.timeSource()),
      id_(stream_id) {}

} // namespace Envoy::Upstream