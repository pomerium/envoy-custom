#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.h"
#include "envoy/extensions/transport_sockets/internal_upstream/v3/internal_upstream.pb.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class ReverseTunnelIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                     public SshIntegrationTest {
public:
  ReverseTunnelIntegrationTest()
      : SshIntegrationTest({"unused"}, Http::CodecType::HTTP1, GetParam()) {
    // concurrency_ = 3;

    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      configureUpstreamTunnelCluster(*bootstrap.mutable_static_resources()->mutable_clusters(1)); // http_cluster_1
    });
  }

  struct ClusterLoadOpts {
    stream_id_t stream_id;
    std::string requested_host;
    uint32_t requested_port;
    uint32_t server_port;
    bool is_dynamic;
  };

  void setClusterLoad(const std::string& cluster_name, ClusterLoadOpts opts) {
    envoy::config::endpoint::v3::ClusterLoadAssignment load;
    load.set_cluster_name(cluster_name);
    auto* endpoint = load.add_endpoints()->add_lb_endpoints();
    auto* socketAddress = endpoint->mutable_endpoint()->mutable_address()->mutable_socket_address();
    socketAddress->set_address(fmt::format("ssh:{}", opts.stream_id));
    socketAddress->set_port_value(opts.server_port);

    pomerium::extensions::ssh::EndpointMetadata endpointMetadata;
    endpointMetadata.mutable_matched_permission()->set_requested_host(opts.requested_host);
    endpointMetadata.mutable_matched_permission()->set_requested_port(opts.requested_port);
    endpointMetadata.mutable_server_port()->set_value(opts.server_port);
    endpointMetadata.mutable_server_port()->set_is_dynamic(opts.is_dynamic);
    (*endpoint
        ->mutable_metadata()
        ->mutable_typed_filter_metadata())["com.pomerium.ssh.endpoint"]
      .PackFrom(endpointMetadata);
    endpoint->set_health_status(envoy::config::core::v3::HealthStatus::HEALTHY);

    for (auto& assignment : load_assignments_) {
      if (assignment.cluster_name() == cluster_name) {
        assignment.MergeFrom(load);
        return;
      }
    }
    load_assignments_.push_back(std::move(load));
    eds_helper_.setEds(load_assignments_);
  }

  void configureUpstreamTunnelCluster(envoy::config::cluster::v3::Cluster& cluster) {
    cluster.clear_upstream_bind_config();
    cluster.clear_type();
    if (!cluster.has_transport_socket()) {
      envoy::extensions::transport_sockets::raw_buffer::v3::RawBuffer raw_buffer;
      cluster.mutable_transport_socket()->set_name("envoy.transport_sockets.raw_buffer");
      cluster.mutable_transport_socket()->mutable_typed_config()->PackFrom(raw_buffer);
    }
    envoy::extensions::transport_sockets::internal_upstream::v3::InternalUpstreamTransport internal_upstream;
    internal_upstream.mutable_transport_socket()->CopyFrom(cluster.transport_socket());
    cluster.mutable_transport_socket()->set_name("envoy.transport_sockets.internal_upstream");
    cluster.mutable_transport_socket()->mutable_typed_config()->PackFrom(internal_upstream);

    pomerium::extensions::ssh::ReverseTunnelCluster reverse_tunnel_cluster;
    reverse_tunnel_cluster.set_name(cluster.name());
    reverse_tunnel_cluster.mutable_eds_config()->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
    reverse_tunnel_cluster.mutable_eds_config()->mutable_path_config_source()->set_path(eds_helper_.edsPath());

    cluster.mutable_cluster_type()->set_name("envoy.clusters.ssh_reverse_tunnel");
    cluster.mutable_cluster_type()->mutable_typed_config()->PackFrom(reverse_tunnel_cluster);
  }

  EdsHelper eds_helper_;
  std::vector<envoy::config::endpoint::v3::ClusterLoadAssignment> load_assignments_;
};

TEST_P(ReverseTunnelIntegrationTest, Test) {
  initialize();
  auto driver = makeSshConnectionDriver();
  ASSERT(driver->connectionDispatcher().ptr() == dispatcher_.get());
  driver->connect();

  const auto httpPort = lookupPort("http");
  ASSERT_TRUE(driver->waitForKex());
  ASSERT_TRUE(driver->startTaskAndWait<Tasks::RequestUserAuthService>());
  ASSERT_TRUE(driver->startTaskAndWait<Tasks::Authenticate>("user", true));
  ASSERT_TRUE(driver->startTaskAndWait<Tasks::RequestReversePortForward>("http-cluster-1", httpPort, httpPort));

  setClusterLoad("http_cluster_1",
                 {
                   .stream_id = driver->streamId(),
                   .requested_host = "http-cluster-1",
                   .requested_port = httpPort,
                   .server_port = httpPort,
                   .is_dynamic = false,
                 });

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto requestHeaders = Http::TestRequestHeaderMapImpl{
    {":method", "GET"},
    {":path", "/"},
    {":scheme", "http"},
    {":authority", "http-cluster-1"},
  };

  auto response = codec_client_->makeHeaderOnlyRequest(requestHeaders);

  // once the request is sent, we should see a new channel open
  uint32_t remote_channel_id{};
  ASSERT_TRUE(driver->startTaskAndWait<Tasks::AcceptReversePortForward>("http-cluster-1", httpPort, 1, &remote_channel_id));
  ASSERT_TRUE(driver->startTaskAndWait<Tasks::WaitForChannelData>(
    1, "GET / HTTP/1.1\r\nhost: http-cluster-1\r\nx-forwarded-proto: http\r\n"));
  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = remote_channel_id,
    .data = "HTTP/1.1 200 OK\r\n\r\n"_bytes,
  });
  driver->startTask<Tasks::SendChannelCloseAndWait>(1, remote_channel_id);
  ASSERT_TRUE(response->waitForEndStream(defaultTimeout()));
  ASSERT_EQ(200, response->headers().Status());
  codec_client_->close(Network::ConnectionCloseType::FlushWrite);
  ASSERT_TRUE(driver->waitAllTasksComplete());
}

INSTANTIATE_TEST_SUITE_P(ReverseTunnelIntegrationTest, ReverseTunnelIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec