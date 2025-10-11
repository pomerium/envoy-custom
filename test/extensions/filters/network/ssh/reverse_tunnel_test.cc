#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.h"
#include "envoy/extensions/transport_sockets/internal_upstream/v3/internal_upstream.pb.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

// Modified from Envoy::EdsHelper which uses a static filepath
class EdsHelper {
public:
  EdsHelper(const std::string& cluster_name)
      : cluster_name_(cluster_name),
        eds_path_(TestEnvironment::writeStringToFileForTest(cluster_name_ + "_eds.pb_text", "")) {
    // Note: the update_success stat is modified by the EDS backend, not by the cluster itself.
    // It is incremented once on startup.
    ++update_successes_;
  }

  void setEds(const envoy::config::endpoint::v3::ClusterLoadAssignment& cluster_load_assignment) {
    // Write to file the DiscoveryResponse and trigger inotify watch.
    envoy::service::discovery::v3::DiscoveryResponse eds_response;
    eds_response.set_version_info(std::to_string(eds_version_++));
    eds_response.set_type_url(Config::TypeUrl::get().ClusterLoadAssignment);
    // Only one resource per file
    eds_response.add_resources()->PackFrom(cluster_load_assignment);

    // Past the initial write, need move semantics to trigger inotify move event that the
    // FilesystemSubscriptionImpl is subscribed to.
    std::string path = TestEnvironment::writeStringToFileForTest(
      cluster_name_ + "_eds.update.pb_text", MessageUtil::toTextProto(eds_response));
    TestEnvironment::renameFile(path, eds_path_);
  }

  void setEdsAndWait(const envoy::config::endpoint::v3::ClusterLoadAssignment& cluster_load_assignment,
                     IntegrationTestServerStats& server_stats) {
    auto counter_name = fmt::format("cluster.{}.update_success", cluster_name_);
    // Make sure the last version has been accepted before setting a new one.
    server_stats.waitForCounterGe(counter_name, update_successes_);
    setEds(cluster_load_assignment);
    // Make sure Envoy has consumed the update now that it is running.
    ++update_successes_;
    server_stats.waitForCounterGe(counter_name, update_successes_);
    RELEASE_ASSERT(update_successes_ == server_stats.counter(counter_name)->value(), "");
  }

  const std::string& edsPath() const { return eds_path_; }

private:
  const std::string cluster_name_;
  const std::string eds_path_;
  uint32_t eds_version_{};
  uint32_t update_successes_{};
};

class ReverseTunnelIntegrationTest : public testing::TestWithParam<std::tuple<int, Network::Address::IpVersion>>,
                                     public SshIntegrationTest {
public:
  ReverseTunnelIntegrationTest()
      : SshIntegrationTest({"unused"}, std::get<1>(GetParam())) {
    concurrency_ = std::get<0>(GetParam());

    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      // note: update eds_helpers_ if this changes
      configureUpstreamTunnelCluster(*bootstrap.mutable_static_resources()->mutable_clusters(1)); // http_cluster_1
      configureUpstreamTunnelCluster(*bootstrap.mutable_static_resources()->mutable_clusters(3)); // tcp_cluster
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

    RELEASE_ASSERT(eds_helpers_.contains(cluster_name), "test bug: invalid cluster name");
    eds_helpers_[cluster_name]->setEdsAndWait(load, *test_server_);
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
    reverse_tunnel_cluster.mutable_eds_config()->mutable_path_config_source()->set_path(eds_helpers_[cluster.name()]->edsPath());

    cluster.mutable_cluster_type()->set_name("envoy.clusters.ssh_reverse_tunnel");
    cluster.mutable_cluster_type()->mutable_typed_config()->PackFrom(reverse_tunnel_cluster);
  }

  // NB: filesystem EDS subscription doesn't work like api-based subscription: it always reports
  // all changed resources, and ignores the resource name filter (for some reason). So we need
  // separate files for each cluster, otherwise they will both get the EDS updates when updating
  // any of them, regardless of the load assignment's cluster_name.
  EdsHelper http_cluster_eds_{"http_cluster_1"};
  EdsHelper tcp_cluster_eds_{"tcp_cluster"};
  std::unordered_map<std::string, EdsHelper*> eds_helpers_{
    {"http_cluster_1", &http_cluster_eds_},
    {"tcp_cluster", &tcp_cluster_eds_},
  };
};

TEST_P(ReverseTunnelIntegrationTest, TestHttp) {
  initialize();
  auto driver = makeSshConnectionDriver();
  RELEASE_ASSERT(driver->connectionDispatcher().ptr() == dispatcher_.get(), "");
  driver->connect();

  const auto httpPort = lookupPort("http");
  ASSERT_TRUE(driver->waitForKex());
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::RequestUserAuthService>().start()));
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::Authenticate>("user", true).start()));
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::RequestReversePortForward>("http-cluster-1", httpPort, httpPort).start()));

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

  auto th = driver->createTask<Tasks::AcceptReversePortForward>("http-cluster-1", httpPort, 1)
              .then(driver->createTask<Tasks::WaitForChannelData>("GET / HTTP/1.1\r\nhost: http-cluster-1\r\nx-forwarded-proto: http\r\n")
                      .then(driver->createTask<Tasks::SendChannelData>("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                              .then(driver->createTask<Tasks::SendChannelCloseAndWait>())))
              .start();

  auto response = codec_client_->makeHeaderOnlyRequest(requestHeaders);
  ASSERT_TRUE(response->waitForEndStream(defaultTimeout()));
  ASSERT_EQ("200", response->headers().Status()->value().getStringView());
  codec_client_->close(Network::ConnectionCloseType::FlushWrite);
  ASSERT_TRUE(driver->wait(th));
  ASSERT_TRUE(driver->disconnect());
}

static std::string testParamsToString(const testing::TestParamInfo<std::tuple<int, Network::Address::IpVersion>>& params) {
  return fmt::format("{}_threads_{}",
                     std::get<0>(params.param),
                     TestUtility::ipVersionToString(std::get<1>(params.param)));
}

INSTANTIATE_TEST_SUITE_P(ReverseTunnelIntegrationTest, ReverseTunnelIntegrationTest,
                         testing::Combine(testing::ValuesIn({1, 4}),
                                          testing::ValuesIn(TestEnvironment::getIpVersionsForTest())),
                         testParamsToString);

class StaticPortForwardTest : public ReverseTunnelIntegrationTest {
public:
  void SetUp() override {
    initialize();
    route_port = lookupPort("tcp");
    driver = makeSshConnectionDriver();
    RELEASE_ASSERT(driver->connectionDispatcher().ptr() == dispatcher_.get(), "");
    driver->connect();
    const auto tcpPort = lookupPort("tcp");
    ASSERT_TRUE(driver->waitForKex());
    ASSERT_TRUE(driver->wait(driver->createTask<Tasks::RequestUserAuthService>().start()));
    ASSERT_TRUE(driver->wait(driver->createTask<Tasks::Authenticate>("user", true).start()));
    ASSERT_TRUE(driver->wait(driver->createTask<Tasks::RequestReversePortForward>("tcp-cluster", tcpPort, tcpPort).start()));

    setClusterLoad(cluster_name,
                   {
                     .stream_id = driver->streamId(),
                     .requested_host = route_name,
                     .requested_port = route_port,
                     .server_port = route_port,
                     .is_dynamic = false,
                   });
  }

  void TearDown() override {
    ASSERT_TRUE(driver->disconnect());
  }

  const std::string route_name = "tcp-cluster";
  const std::string cluster_name = "tcp_cluster";
  uint32_t route_port{};
  std::shared_ptr<SshConnectionDriver> driver;
};

TEST_P(StaticPortForwardTest, PingClientToServer_ClientCloses) {
  const uint32_t channel_id = 1;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, channel_id)
              .then(driver->createTask<Tasks::WaitForChannelData>("ping")
                      .then(driver->createTask<Tasks::SendChannelData>("pong")
                              .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>())))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  EXPECT_TRUE(tcp_client->write("ping"));
  tcp_client->waitForData("pong");
  tcp_client->close();

  EXPECT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, PingClientToServer_ServerCloses) {
  const uint32_t channel_id = 1;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, channel_id)
              .then(driver->createTask<Tasks::WaitForChannelData>("ping")
                      .then(driver->createTask<Tasks::SendChannelData>("pong")
                              .then(driver->createTask<Tasks::SendChannelCloseAndWait>())))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  EXPECT_TRUE(tcp_client->write("ping"));
  tcp_client->waitForData("pong");
  tcp_client->waitForDisconnect();
  tcp_client->close();

  EXPECT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, PingServerToClient_ClientCloses) {
  const uint32_t channel_id = 1;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, channel_id)
              .then(driver->createTask<Tasks::SendChannelData>("ping")
                      .then(driver->createTask<Tasks::WaitForChannelData>("pong")
                              .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>())))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForData("ping");
  EXPECT_TRUE(tcp_client->write("pong"));
  tcp_client->close();

  EXPECT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, PingServerToClient_ServerCloses) {
  const uint32_t channel_id = 1;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, channel_id)
              .then(driver->createTask<Tasks::SendChannelData>("ping")
                      .then(driver->createTask<Tasks::WaitForChannelData>("pong")
                              .then(driver->createTask<Tasks::SendChannelCloseAndWait>())))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForData("ping");
  EXPECT_TRUE(tcp_client->write("pong"));
  tcp_client->waitForDisconnect();
  tcp_client->close();

  EXPECT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, ServerRejectsChannelOpen) {
  auto th = driver->createTask<Tasks::RejectReversePortForward>(route_name, route_port)
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForDisconnect();
  tcp_client->close();

  EXPECT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, UnexpectedClientDisconnect) {
  auto th = driver->createTask<Tasks::RejectReversePortForward>(route_name, route_port)
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForDisconnect();
  tcp_client->close();

  EXPECT_TRUE(driver->wait(th));
}

INSTANTIATE_TEST_SUITE_P(StaticPortForward, StaticPortForwardTest,
                         testing::Combine(testing::ValuesIn({1, 4}),
                                          testing::ValuesIn(TestEnvironment::getIpVersionsForTest())),
                         testParamsToString);

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec