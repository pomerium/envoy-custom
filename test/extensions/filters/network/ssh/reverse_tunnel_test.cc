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
    concurrency_ = 3;

    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      configureUpstreamTunnelCluster(*bootstrap.mutable_static_resources()->mutable_clusters(1)); // http_cluster_1
    });
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
};

TEST_P(ReverseTunnelIntegrationTest, Test) {
  initialize();
  auto driver = makeSshConnectionDriver();
  driver->connect();

  const auto httpPort = lookupPort("http");
  ASSERT_TRUE(driver->waitForKex());
  ASSERT_TRUE(driver->runTask(Tasks::RequestUserAuthService{}));
  ASSERT_TRUE(driver->runTask(Tasks::Authenticate{"user", true}));
  ASSERT_TRUE(driver->runTask(Tasks::RequestReversePortForward{"http-cluster-1", httpPort, httpPort}));

  envoy::config::endpoint::v3::ClusterLoadAssignment load;
  load.set_cluster_name("http_cluster_1");
  auto* endpoint = load.add_endpoints()->add_lb_endpoints();
  auto* socketAddress = endpoint->mutable_endpoint()->mutable_address()->mutable_socket_address();
  socketAddress->set_address(fmt::format("ssh:{}", driver->streamId()));
  socketAddress->set_port_value(httpPort);

  pomerium::extensions::ssh::EndpointMetadata endpointMetadata;
  endpointMetadata.mutable_matched_permission()->set_requested_host("http-cluster-1");
  endpointMetadata.mutable_matched_permission()->set_requested_port(httpPort);
  endpointMetadata.mutable_server_port()->set_value(httpPort);
  endpointMetadata.mutable_server_port()->set_is_dynamic(false);
  (*endpoint
      ->mutable_metadata()
      ->mutable_typed_filter_metadata())["com.pomerium.ssh.endpoint"]
    .PackFrom(endpointMetadata);
  endpoint->set_health_status(envoy::config::core::v3::HealthStatus::HEALTHY);
  eds_helper_.setEds({load});

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
  ASSERT_TRUE(driver->runTask(Tasks::AcceptReversePortForward{"http-cluster-1", httpPort, 1, &remote_channel_id}));
  ASSERT_TRUE(driver->runTask(Tasks::WaitForChannelData{
    1, "GET / HTTP/1.1\r\nhost: http-cluster-1\r\nx-forwarded-proto: http\r\n"}));
  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = remote_channel_id,
    .data = "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n"_bytes,
  });
  ASSERT_TRUE(response->waitForEndStream(defaultTimeout()));
  ASSERT_TRUE(driver->runTask(Tasks::WaitForChannelClose{1}));
  codec_client_->close();
}

INSTANTIATE_TEST_SUITE_P(ReverseTunnelIntegrationTest, ReverseTunnelIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec