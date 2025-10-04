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
      : SshIntegrationTest({{"http-tunnel", "http_tunnel"}}, Http::CodecType::HTTP1, GetParam()) {
    concurrency_ = 3;

    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      ASSERT(bootstrap.mutable_static_resources()->clusters_size() == 2);
      auto* tunnel_cluster = bootstrap.mutable_static_resources()->add_clusters();
      tunnel_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      configureUpstreamTunnelCluster(*tunnel_cluster);
      tunnel_cluster->set_name("http_tunnel");

      eds_helper_.setEds({});
    });
  }

  void createUpstreams() override {
    SshIntegrationTest::createUpstreams();
    http_tunnel_upstream_ = &addFakeUpstream(Http::CodecType::HTTP1);
  }

  void configureUpstreamTunnelCluster(envoy::config::cluster::v3::Cluster& cluster) {
    cluster.clear_upstream_bind_config();
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

  Envoy::FakeUpstream* http_tunnel_upstream_;
  EdsHelper eds_helper_;
};

TEST_P(ReverseTunnelIntegrationTest, Test) {
  initialize();
  auto driver = makeSshConnectionDriver();
  driver->connect();

  ASSERT_TRUE(driver->waitForKex(isDebuggerAttached() ? absl::Hours(1) : absl::Seconds(10)));
  ASSERT_TRUE(driver->runTask(Tasks::RequestUserAuthService{}));
  ASSERT_TRUE(driver->runTask(Tasks::Authenticate{}));

  // codec_client_ = makeHttpConnection(lookupPort("http"));
  // auto response_one = sendRequestAndWaitForResponse(default_request_headers_, 100,
  //                                                   default_response_headers_, 100, 0);
}

INSTANTIATE_TEST_SUITE_P(ReverseTunnelIntegrationTest, ReverseTunnelIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec