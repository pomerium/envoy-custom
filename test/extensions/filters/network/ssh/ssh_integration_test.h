#pragma once

#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_upstream.h"
#include "test/integration/http_integration.h"
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
    eds_response.set_type_url(Config::TestTypeUrl::get().ClusterLoadAssignment);
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

class FakeStreamShimImpl : public FakeStreamShim {
public:
  explicit FakeStreamShimImpl(std::unique_ptr<FakeStream> real_fake)
      : real_fake_(std::move(real_fake)) {}

  void startGrpcStream() override {
    return real_fake_->startGrpcStream();
  }
  testing::AssertionResult waitForGrpcMessage(Envoy::Event::Dispatcher& client_dispatcher,
                                              Protobuf::Message& message,
                                              std::chrono::milliseconds timeout) override {
    return real_fake_->waitForGrpcMessage(client_dispatcher, message, timeout);
  }

  void sendGrpcMessage(const Protobuf::Message& message) override {
    return real_fake_->sendGrpcMessage(message);
  }

  std::unique_ptr<FakeStream> real_fake_;
};

class FakeHttpConnectionShimImpl : public FakeHttpConnectionShim {
public:
  explicit FakeHttpConnectionShimImpl(std::unique_ptr<FakeHttpConnection> real_fake)
      : real_fake_(std::move(real_fake)) {}

  [[nodiscard]]
  testing::AssertionResult waitForNewStream(Envoy::Event::Dispatcher& client_dispatcher,
                                            std::unique_ptr<FakeStreamShim>& stream,
                                            std::chrono::milliseconds timeout) override {
    std::unique_ptr<FakeStream> real;
    auto ret = real_fake_->waitForNewStream(client_dispatcher, real, timeout);
    stream = std::make_unique<FakeStreamShimImpl>(std::move(real));
    return ret;
  }

  [[nodiscard]]
  testing::AssertionResult close(Network::ConnectionCloseType close_type,
                                 std::chrono::milliseconds timeout) override {
    return real_fake_->close(close_type, timeout);
  }

  std::unique_ptr<FakeHttpConnection> real_fake_;
};

class FakeUpstreamShimImpl : public FakeUpstreamShim {
public:
  FakeUpstreamShimImpl() = default;

  explicit FakeUpstreamShimImpl(FakeUpstream* fake_upstream)
      : fake_upstream_(fake_upstream) {}

  [[nodiscard]]
  testing::AssertionResult waitForHttpConnection(Envoy::Event::Dispatcher& client_dispatcher,
                                                 std::unique_ptr<FakeHttpConnectionShim>& connection,
                                                 std::chrono::milliseconds timeout) override;

  [[nodiscard]]
  testing::AssertionResult configureSshUpstream(std::shared_ptr<SshFakeUpstreamHandlerOpts> opts,
                                                Server::Configuration::ServerFactoryContext& ctx) override;

  void cleanup() override;

private:
  FakeUpstream* fake_upstream_{};
  Envoy::Event::TimerPtr timer_;
  std::unique_ptr<SshFakeUpstreamHandler> handler_;
};

class SshIntegrationTest : public SecretsProviderImpl,
                           public HttpIntegrationTest {
  // Implementation note:
  // SecretsProviderImpl has to be a separate base class, initialized before HttpIntegrationTest,
  // and must create the ssh keys. The HttpIntegrationTest constructor needs the string config,
  // which we need to format using the generated keys. If we stored the keys in SshIntegrationTest
  // and initialized them e.g. inside defaultConfig(), they would be deleted when the members of
  // SshIntegrationTest are default-initialized, which happens after the HttpIntegrationTest
  // constructor completes.
protected:
  SshIntegrationTest(std::vector<std::string> ssh_routes, Network::Address::IpVersion version);
  ~SshIntegrationTest();

  void initialize() override;
  void cleanup();

  std::string localhost() const {
    return (version_ == Network::Address::IpVersion::v4)
             ? "127.0.0.1"
             : "::1";
  }

  std::string defaultConfig(const std::vector<std::string>& routes);

  std::shared_ptr<SshConnectionDriver> makeSshConnectionDriver();
  IntegrationTcpClientPtr makeTcpConnectionWithServerName(uint32_t port, const std::string& server_name);

  AssertionResult configureSshUpstream(SshFakeUpstreamHandlerOpts&& opts, size_t upstream_index = 0);
  void configureUpstreamTunnelCluster(envoy::config::cluster::v3::Cluster& cluster);

  struct ClusterLoadOpts {
    stream_id_t stream_id;
    std::string requested_host;
    uint32_t requested_port;
    uint32_t server_port;
    bool is_dynamic;
  };

  void setClusterLoad(const std::string& cluster_name, std::vector<ClusterLoadOpts> endpoint_opts);

  FakeUpstream& addFakeUpstream(Http::CodecType type, const std::string& name) {
    auto config = configWithType(type);
    config.dispatcher_name_ = name;
    fake_upstreams_.emplace_back(std::make_unique<FakeUpstream>(0, version_, config));
    return *fake_upstreams_.back();
  }

  int mgmtClusterIndex() const { return 0; }
  int httpUpstreamClusterIndex() const { return 1 + static_cast<int>(ssh_upstreams_.size()); }
  int grpcUpstreamClusterIndex() const { return 1 + static_cast<int>(ssh_upstreams_.size()) + 1; }
  int tcpUpstreamClusterIndex() const { return 1 + static_cast<int>(ssh_upstreams_.size()) + 2; }

  FakeUpstreamShimImpl mgmt_upstream_;
  std::vector<FakeUpstreamShimImpl> ssh_upstreams_;
  FakeUpstreamShimImpl http_upstream_1_;
  FakeUpstreamShimImpl http_upstream_2_;
  FakeUpstreamShimImpl tcp_upstream_;

  // NB: filesystem EDS subscription doesn't work like api-based subscription: it always reports
  // all changed resources, and ignores the resource name filter (for some reason). So we need
  // separate files for each cluster, otherwise they will both get the EDS updates when updating
  // any of them, regardless of the load assignment's cluster_name.
  EdsHelper http_cluster_eds_{"http_cluster_1"};
  EdsHelper grpc_cluster_eds_{"http_cluster_2"};
  EdsHelper tcp_cluster_eds_{"tcp_cluster"};
  std::unordered_map<std::string, EdsHelper*> eds_helpers_{
    {"http_cluster_1", &http_cluster_eds_},
    {"http_cluster_2", &grpc_cluster_eds_},
    {"tcp_cluster", &tcp_cluster_eds_},
  };
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec