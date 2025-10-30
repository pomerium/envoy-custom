#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/reverse_tunnel.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.h"
#include "envoy/extensions/transport_sockets/internal_upstream/v3/internal_upstream.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.validate.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "gtest/gtest.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_common.h"

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

class BaseReverseTunnelIntegrationTest : public testing::Test,
                                         public SshIntegrationTest {
public:
  BaseReverseTunnelIntegrationTest(Network::Address::IpVersion version)
      : SshIntegrationTest({"unused"}, version) {

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

  void setClusterLoad(const std::string& cluster_name, std::vector<ClusterLoadOpts> endpoint_opts) {
    envoy::config::endpoint::v3::ClusterLoadAssignment load;
    load.set_cluster_name(cluster_name);
    for (auto opts : endpoint_opts) {
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
    }
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

class HttpReverseTunnelIntegrationTest : public BaseReverseTunnelIntegrationTest,
                                         public testing::WithParamInterface<Network::Address::IpVersion> {
public:
  HttpReverseTunnelIntegrationTest()
      : BaseReverseTunnelIntegrationTest(GetParam()) {}
};

TEST_P(HttpReverseTunnelIntegrationTest, TestHttp) {
  initialize();
  auto driver = makeSshConnectionDriver();
  RELEASE_ASSERT(driver->connectionDispatcher().ptr() == dispatcher_.get(), "");
  driver->connect();

  const auto httpPort = lookupPort("http");
  ASSERT_TRUE(driver->waitForKex());
  ASSERT_TRUE(driver->waitForUserAuth());
  ASSERT_TRUE(driver->requestReversePortForward("http-cluster-1", httpPort, httpPort));

  setClusterLoad("http_cluster_1",
                 {{
                   .stream_id = *driver->serverStreamId(),
                   .requested_host = "http-cluster-1",
                   .requested_port = httpPort,
                   .server_port = httpPort,
                   .is_dynamic = false,
                 }});

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
  ASSERT_TRUE(response->waitForEndStream(driver->defaultTimeout()));
  ASSERT_EQ("200", response->headers().Status()->value().getStringView());
  codec_client_->close(Network::ConnectionCloseType::FlushWrite);
  ASSERT_TRUE(driver->wait(th));
  ASSERT_TRUE(driver->disconnect());
}

class StaticPortForwardTest : public BaseReverseTunnelIntegrationTest,
                              public testing::WithParamInterface<Network::Address::IpVersion> {
public:
  StaticPortForwardTest()
      : BaseReverseTunnelIntegrationTest(GetParam()) {}

  void SetUp() override {
    initialize();
    route_port = lookupPort("tcp");
    driver = makeSshConnectionDriver();
    RELEASE_ASSERT(driver->connectionDispatcher().ptr() == dispatcher_.get(), "");
    driver->connect();
    const auto tcpPort = lookupPort("tcp");
    ASSERT_TRUE(driver->waitForKex());
    ASSERT_TRUE(driver->waitForUserAuth());
    ASSERT_TRUE(driver->requestReversePortForward("tcp-cluster", tcpPort, tcpPort));

    setClusterLoad(cluster_name,
                   {{
                     .stream_id = *driver->serverStreamId(),
                     .requested_host = route_name,
                     .requested_port = route_port,
                     .server_port = route_port,
                     .is_dynamic = false,
                   }});
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
                              .then(driver->createTask<Tasks::WaitForChannelEOF>()
                                      .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  EXPECT_TRUE(tcp_client->write("ping"));
  tcp_client->waitForData("pong");
  tcp_client->close();

  ASSERT_TRUE(driver->wait(th));
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

  ASSERT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, PingServerToClient_ClientCloses) {
  const uint32_t channel_id = 1;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, channel_id)
              .then(driver->createTask<Tasks::SendChannelData>("ping")
                      .then(driver->createTask<Tasks::WaitForChannelData>("pong")
                              .then(driver->createTask<Tasks::WaitForChannelEOF>()
                                      .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForData("ping");
  EXPECT_TRUE(tcp_client->write("pong"));
  tcp_client->close();

  ASSERT_TRUE(driver->wait(th));
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

  ASSERT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, ServerRejectsChannelOpen) {
  auto th = driver->createTask<Tasks::RejectReversePortForward>(route_name, route_port)
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForDisconnect();
  tcp_client->close();

  ASSERT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, UnexpectedClientDisconnect) {
  auto th = driver->createTask<Tasks::RejectReversePortForward>(route_name, route_port)
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForDisconnect();
  tcp_client->close();

  ASSERT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, ImmediateServerEOFClose) {
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .then(driver->createTask<Tasks::SendChannelCloseAndWait>(Tasks::SendEOF(true)))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForDisconnect();
  tcp_client->close();

  ASSERT_TRUE(driver->wait(th));
}

static constexpr auto stat_window_adjustment_paused =
  "cluster.tcp_cluster.ssh_reverse_tunnel.upstream_flow_control_window_adjustment_paused_total";
static constexpr auto stat_window_adjustment_resumed =
  "cluster.tcp_cluster.ssh_reverse_tunnel.upstream_flow_control_window_adjustment_resumed_total";
static constexpr auto stat_local_window_exhausted =
  "cluster.tcp_cluster.ssh_reverse_tunnel.upstream_flow_control_local_window_exhausted_total";
static constexpr auto stat_downstream_high_watermark =
  "cluster.tcp_cluster.ssh_reverse_tunnel.downstream_flow_control_high_watermark_activated_total";
static constexpr auto stat_downstream_low_watermark =
  "cluster.tcp_cluster.ssh_reverse_tunnel.downstream_flow_control_low_watermark_activated_total";

class SendDataUntilRemoteWindowExhausted : public Task<Tasks::Channel, Tasks::Channel> {
public:
  SendDataUntilRemoteWindowExhausted(Stats::Counter& local_window_exhausted_counter, size_t* total_bytes_written = nullptr)
      : local_window_exhausted_counter_(local_window_exhausted_counter),
        total_bytes_written_out_(total_bytes_written) {}
  void start(Tasks::Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    remote_window_ = channel.initial_window_size;
    max_packet_size_ = channel.max_packet_size;

    callbacks_->setTimeout(default_timeout_, "SendDataUntilRemoteWindowExhausted");
    callbacks_->loop(std::chrono::milliseconds(0), [this] {
      if (remote_window_ == 0) {
        if (local_window_exhausted_counter_.value() == 1) {
          if (total_bytes_written_out_ != nullptr) {
            *total_bytes_written_out_ = total_bytes_written_;
          }
          taskSuccess(channel_);
        } else {
          std::this_thread::yield();
        }
        return;
      }

      wire::ChannelDataMsg packet;
      packet.recipient_channel = channel_.remote_id;
      // We want to be able to observe receiving a window adjust around halfway (at least once,
      // probably several times depending on default buffer sizes + kernel buffer sizes), then
      // at some point no longer receiving them until the window drops to 0.
      packet.data->resize(16384);
      remote_window_ -= packet.data->size();
      total_bytes_written_ += packet.data->size();
      callbacks_->sendMessage(std::move(packet));
    });
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::ChannelWindowAdjustMsg& adjust) {
        remote_window_ += adjust.bytes_to_add;
        return Break;
      },
      DEFAULT_CONTINUE);
  }

  uint32_t remote_window_{};
  uint32_t max_packet_size_{};
  size_t total_bytes_written_{};
  Tasks::Channel channel_;
  Stats::Counter& local_window_exhausted_counter_;
  size_t* total_bytes_written_out_{};
};

class ReceiveDataUntilLocalWindowExhausted : public Task<Tasks::Channel, Tasks::Channel> {
public:
  void start(Tasks::Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    local_window_ = channel.upstream_initial_window_size;
  }

  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::ChannelDataMsg& msg) {
        if (msg.data->size() > local_window_) {
          taskFailure(absl::InternalError("local window exceeded"));
          return Break;
        }
        ENVOY_LOG_MISC(debug, ">> packet: '{}'", std::string_view(reinterpret_cast<char*>(msg.data->data()), std::min(32uz, msg.data->size())));
        total_bytes_received_ += msg.data->size();
        ENVOY_LOG_MISC(debug, "read {} bytes; total={}", msg.data->size(), total_bytes_received_);
        local_window_ -= msg.data->size();
        if (local_window_ == 0) {
          taskSuccess(channel_);
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }

  uint32_t local_window_{};
  size_t total_bytes_received_{};
  Tasks::Channel channel_;
};

class SendDataAndWaitForClose : public Tasks::WaitForChannelCloseByPeer {
public:
  void start(Tasks::Channel channel) override {
    Tasks::WaitForChannelCloseByPeer::start(channel);
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{1},
    });
  }
};

TEST_P(StaticPortForwardTest, UpstreamFlowControl_ClientReadDisabledUntilChannelClosed) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  downstream->readDisable(true);

  auto local_window_exhausted = test_server_->counter(stat_local_window_exhausted);
  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .then(driver->createTask<SendDataUntilRemoteWindowExhausted>(*local_window_exhausted)
              .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))
      .start()));

  EXPECT_EQ(1, test_server_->counter(stat_window_adjustment_paused)->value());
  EXPECT_EQ(0, test_server_->counter(stat_window_adjustment_resumed)->value());

  // The TCP proxy will set detectEarlyCloseWhenReadDisabled(false) on server connections to make
  // sure all data is proxied before close. At this point, that server connection will be
  // read-disabled.
  // If a connection is set to not detect early close when read disabled, it will only be listening
  // to Write file events and not Close events. When the reverse tunnel channel is closed, it will
  // send an EOF file event (read+close) that will not be received by the server connection.
  // However, the remote io handle sets receive_data_end_stream_ to true, keeping track of the
  // received EOF. This will be checked the next time the io handle is read from.
  // When we re-enable reads from the downstream connection, it will flush the write buffer,
  // eventually triggering the write buffer low watermark event. This will cause the upstream
  // server connection to be read-enabled again, then the following sequence occurs:
  // 1. ConnectionImpl::onFileEvent() is invoked with a Read event
  // 2. ConnectionImpl::onFileEvent() calls ConnectionImpl::onReadReady()
  // 3. ConnectionImpl::onReadReady() calls RawBufferSocket::doRead()
  // 4. RawBufferSocket::doRead() calls UserSpace::IoHandleImpl::read()
  // 5. UserSpace::IoHandleImpl::read() sees no pending received data + the EOF flag, and returns
  //    {0 /*bytes read*/, Api::IoError::none()}
  // 6. RawBufferSocket::doRead() sees that return status (0 bytes read, no error) and
  //    returns an IoResult with action PostIoAction::Close
  // 7. ConnectionImpl::onReadReady() sees PostIoAction::Close and calls
  //    ConnectionImpl::closeThroughFilterManager() with ConnectionEvent::RemoteClose
  // 8. IntegrationTcpClient::ConnectionCallbacks::onEvent() receives the RemoteClose event
  //    and sets its disconnected_ flag to true
  // 9. IntegrationTcpClient::waitForDisconnect() sees disconnected_ is true and returns.
  downstream->readDisable(false);
  downstream->waitForDisconnect(true);

  EXPECT_EQ(1, test_server_->counter(stat_window_adjustment_paused)->value());
  // If the channel is closed while the server connection is read-disabled, it should not wake up
  // the io handle with a read event after flushing its write buffer, since it has already been
  // closed for writing.
  EXPECT_EQ(0, test_server_->counter(stat_window_adjustment_resumed)->value());

  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamFlowControl_ClientReadDisabledThenEnabledBeforeChannelClose) {
  // As above, except re-enable the downstream before closing the channel
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  downstream->readDisable(true);

  auto local_window_exhausted = test_server_->counter(stat_local_window_exhausted);

  size_t total_bytes_written{};
  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .saveOutput(&channel)
      .then(driver->createTask<SendDataUntilRemoteWindowExhausted>(*local_window_exhausted, &total_bytes_written))
      .start()));

  EXPECT_EQ(1, test_server_->counter(stat_window_adjustment_paused)->value());
  EXPECT_EQ(0, test_server_->counter(stat_window_adjustment_resumed)->value());

  auto th = driver->createTask<Tasks::WaitForChannelMsg<wire::ChannelWindowAdjustMsg>>().start(channel);
  downstream->readDisable(false);
  // Make sure the server sends us a window adjust message
  ASSERT_TRUE(driver->wait(th));
  // Window adjustments should be enabled immediately in response to the upstream socket re-enabling
  // read events on its io handle.
  EXPECT_EQ(1, test_server_->counter(stat_window_adjustment_resumed)->value());

  // all the data should be flushed
  EXPECT_TRUE(downstream->waitForData(total_bytes_written, driver->defaultTimeout()));
  downstream->clearData();

  // We should be able to send data again
  auto th2 = driver->createTask<Tasks::SendChannelData>("ping")
               .then(driver->createTask<Tasks::WaitForChannelData>("pong")
                       .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))
               .start(channel);
  downstream->waitForData("ping");
  EXPECT_TRUE(downstream->write("pong"));
  ASSERT_TRUE(driver->wait(th2));

  downstream->waitForDisconnect(true);
  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamFlowControl_UpstreamIgnoresWindow) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  downstream->readDisable(true);
  auto local_window_exhausted = test_server_->counter(stat_local_window_exhausted);

  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .then(driver->createTask<SendDataUntilRemoteWindowExhausted>(*local_window_exhausted)
              .then(driver->createTask<SendDataAndWaitForClose>()))
      .start()));

  downstream->readDisable(false); // Won't receive disconnect while read-disabled
  downstream->waitForDisconnect(true);

  EXPECT_EQ(1, test_server_->counter(stat_window_adjustment_paused)->value());
  EXPECT_EQ(0, test_server_->counter(stat_window_adjustment_resumed)->value());

  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamFlowControl_DownstreamDisconnectsAfterReadEnable) {
  // This exercises logic that sometimes depends on the order in which events are invoked; run it
  // several times to avoid flakes (hopefully)
  for (int i = 0; i < 10; i++) {
    auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
    downstream->readDisable(true);
    auto local_window_exhausted = test_server_->counter(stat_local_window_exhausted);
    local_window_exhausted->reset();

    Tasks::Channel channel;
    ASSERT_TRUE(driver->wait(
      driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
        .saveOutput(&channel)
        .then(driver->createTask<SendDataUntilRemoteWindowExhausted>(*local_window_exhausted))
        .start()));

    downstream->readDisable(false);
    downstream->close(Network::ConnectionCloseType::AbortReset);
    ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForChannelCloseByPeer>().start(channel)));
  }
}

TEST_P(StaticPortForwardTest, DownstreamFlowControl) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                             .saveOutput(&channel)
                             .start()));
  uint32_t upstream_window = channel.upstream_initial_window_size;

  auto th = driver->createTask<ReceiveDataUntilLocalWindowExhausted>()
              .start(channel);
  uint32_t n = 0;
  while (upstream_window > 0) {
    std::string buf(std::min(upstream_window, 16384u), '-');
    auto pfx = fmt::format("packet {}", n++);
    buf.replace(0, pfx.size(), pfx);
    upstream_window -= buf.size();
    EXPECT_TRUE(downstream->write(buf, false, true));
  }
  ENVOY_LOG_MISC(debug, "test: sent {} bytes", channel.upstream_initial_window_size - upstream_window);

  ASSERT_TRUE(driver->wait(th));

  // The upstream window is exhausted, but the read path buffers are empty as all data has been
  // written to the upstream. We can write more data but it will be buffered and not flushed to
  // the upstream yet.
  std::string data(2uz * 1024 * 1024, 'a');
  ASSERT_TRUE(downstream->write(data, false, true));

  // Flush and close the downstream connection. The tunnel channel should be read-disabled at this
  // point, and is waiting for more window space from the upstream. This should be buffered at the
  // tcp proxy client connection but not written to the io handle.
  downstream->close(Network::ConnectionCloseType::FlushWrite);

  // Once we receive a window adjustment from the upstream, the remaining buffered data should be
  // written, then the channel should be immediately closed.
  // Test multiple window adjusts required to read all the data
  data.resize(data.size() - 10);
  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::SendWindowAdjust>(10)
      .then(driver->createTask<Tasks::WaitForChannelData>("aaaaaaaaaa")
              .then(driver->createTask<Tasks::SendWindowAdjust>(data.size()) // 10 bytes removed above
                      .then(driver->createTask<Tasks::WaitForChannelData>(data)
                              .then(driver->createTask<Tasks::WaitForChannelEOF>()
                                      .then(driver->createTask<Tasks::SendChannelCloseAndWait>(Tasks::SendEOF(false), Tasks::ExpectEOF(false)))))))
      .start(channel)));

  // Flow control may or may not have been triggered during the first set of writes, but all buffers
  // should be empty now so it will have been deactivated the same number of times it was activated.
  auto hwm = test_server_->counter(stat_downstream_high_watermark)->value();
  test_server_->waitForCounterEq(stat_downstream_low_watermark, hwm);
}

TEST_P(StaticPortForwardTest, UpstreamSendsInvalidMessageAfterBacklogThenDisconnects) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                             .saveOutput(&channel)
                             .start()));

  for (int i = 0; i < 10000; i++) {
    driver->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{1},
    });
  }
  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = channel.remote_id,
    .data = bytes(wire::ChannelMaxPacketSize + 1, 0),
  });
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::SendChannelCloseAndWait>().start(channel)));
  downstream->waitForDisconnect();
  downstream->close();
}

TEST_P(StaticPortForwardTest, DownstreamDisconnectsDuringWriteBacklog) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                             .saveOutput(&channel)
                             .start()));

  for (int i = 0; i < 10000; i++) {
    driver->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{1},
    });
  }
  downstream->close(Network::ConnectionCloseType::AbortReset);
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForChannelCloseByPeer>().start(channel)));
}

TEST_P(StaticPortForwardTest, UpstreamSendsLargeMessageThenDownstreamDisconnects) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                             .saveOutput(&channel)
                             .start()));

  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = channel.remote_id,
    .data = bytes(wire::ChannelMaxPacketSize, 0),
  });
  downstream->close(Network::ConnectionCloseType::AbortReset);
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForChannelCloseByPeer>().start(channel)));
}

class SendTooLargePacket : public Task<Tasks::Channel, Tasks::Channel> {
public:
  void start(Tasks::Channel channel) override {
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes(channel.max_packet_size + 1, 0),
    });
    taskSuccess(channel);
  }
  MiddlewareResult onMessageReceived(wire::Message&) override { return Continue; }
};

TEST_P(StaticPortForwardTest, UpstreamPacketTooLarge) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .then(driver->createTask<SendTooLargePacket>()
              .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>()))
      .start()));

  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamPacketEmpty) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  // this should be a no-op
  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .then(driver->createTask<Tasks::SendChannelData>("")
              .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))
      .start()));

  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamSendsInvalidWindowAdjust) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .then(driver->createTask<Tasks::SendWindowAdjust>(std::numeric_limits<uint32_t>::max())
              .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>()))
      .start()));

  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamSendsUnexpectedChannelMessage) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .saveOutput(&channel)
              .start();

  ASSERT_TRUE(driver->wait(th));

  auto th2 = driver->createTask<Tasks::WaitForDisconnectWithError>("received unexpected message on forwarded-tcpip channel")
               .start();

  driver->sendMessage(wire::ChannelExtendedDataMsg{
    .recipient_channel = channel.remote_id,
  });
  ASSERT_TRUE(driver->wait(th2));

  downstream->close();
}

TEST_P(StaticPortForwardTest, UpstreamEOF) {
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .then(driver->createTask<Tasks::SendChannelEOF>()
                      .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>()))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForDisconnect();
  tcp_client->close();

  ASSERT_TRUE(driver->wait(th));
}

TEST_P(StaticPortForwardTest, BlockDownstreamSocksPacket) {
  // See RemoteStreamHandler::initialize() for details
  for (auto hdr : {"\x05\x01\x00"sv, "\x05"sv, "\x04"sv}) {
    auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

    auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>())
                .start();
    ASSERT_TRUE(downstream->write(std::string(hdr), false, true));
    downstream->waitForDisconnect();
    ASSERT_TRUE(driver->wait(th));
  }
}

class StaticPortForwardWithHalfCloseTest : public StaticPortForwardTest {
public:
  using StaticPortForwardTest::StaticPortForwardTest;

  void SetUp() override {
    enableHalfClose(true);
    StaticPortForwardTest::SetUp();
  }
};

TEST_P(StaticPortForwardWithHalfCloseTest, DownstreamHalfClose) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .saveOutput(&channel)
              .then(driver->createTask<Tasks::WaitForChannelData>("half close")
                      .then(driver->createTask<Tasks::WaitForChannelMsg<wire::ChannelEOFMsg>>()))
              .start();

  ASSERT_TRUE(downstream->write("half close", true, true));
  ASSERT_TRUE(driver->wait(th));

  // downstream is half-closed, but can still read
  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = channel.remote_id,
    .data = "testing"_bytes,
  });
  downstream->waitForData("testing");
  // Once the upstream closes, the downstream is closed

  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::SendChannelCloseAndWait>(Tasks::SendEOF(false), Tasks::ExpectEOF(false))
      .start(channel)));
  downstream->waitForDisconnect();
}

TEST_P(StaticPortForwardWithHalfCloseTest, UpstreamHalfClose) {
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .then(driver->createTask<Tasks::SendChannelEOF>()
                      .then(driver->createTask<Tasks::WaitForChannelEOF>()
                              .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>(Tasks::ExpectEOF(false)))))
              .start();

  auto tcp_client = makeTcpConnectionWithServerName(route_port, route_name);
  tcp_client->waitForHalfClose();
  EXPECT_TRUE(tcp_client->write("", true));
  // Don't call waitForDisconnect() here, it only checks for RemoteClose. This should raise LocalClose

  EXPECT_TRUE(driver->wait(th));
  driver->close();
}

TEST_P(StaticPortForwardTest, DownstreamClosesAbruptly) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                             .saveOutput(&channel)
                             .start()));

  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = channel.remote_id,
    .data = randomBytes(1024),
  });
  downstream->close(Network::ConnectionCloseType::AbortReset);
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForChannelCloseByPeer>().start(channel)));
}

TEST_P(StaticPortForwardTest, DownstreamClosesAbruptly2) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
                             .saveOutput(&channel)
                             .start()));

  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = channel.remote_id,
    .data = randomBytes(1024),
  });
  downstream->close(Network::ConnectionCloseType::AbortReset);
  driver->sendMessage(wire::ChannelDataMsg{
    .recipient_channel = channel.remote_id,
    .data = randomBytes(1024),
  });
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForChannelCloseByPeer>().start(channel)));
}

class RejectChannelOpenRequests : public Task<> {
public:
  void start() override {}

  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::ChannelOpenMsg& open_msg) {
        callbacks_->sendMessage(wire::ChannelOpenFailureMsg{
          .recipient_channel = open_msg.sender_channel,
        });
        return Break;
      },
      DEFAULT_CONTINUE);
  };
};

TEST_P(StaticPortForwardTest, UpstreamDisconnectsBeforeInitialization) {
  std::vector<IntegrationTcpClientPtr> downstreams;
  driver->createTask<RejectChannelOpenRequests>().start();
  for (int i = 0; i < 10; i++) {
    downstreams.push_back(makeTcpConnectionWithServerName(route_port, route_name));
  }
  driver->close();
  for (auto& downstream : downstreams) {
    downstream->waitForDisconnect(true);
    downstream->close(Network::ConnectionCloseType::AbortReset);
  }
}

TEST_P(StaticPortForwardTest, HostDrainClosesDownstreamConnections) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  Tasks::Channel channel;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .saveOutput(&channel)
              .then(driver->createTask<Tasks::SendChannelData>("ping")
                      .then(driver->createTask<Tasks::WaitForChannelData>("pong")))
              .start();

  // Wait for a simple send/receive to make sure the remote stream handler is initialized
  downstream->waitForData("ping");
  EXPECT_TRUE(downstream->write("pong"));
  ASSERT_TRUE(driver->wait(th));

  // Remove the host
  auto th2 = driver->createTask<Tasks::WaitForChannelCloseByPeer>()
               .start(channel);
  setClusterLoad(cluster_name, {});
  ASSERT_TRUE(driver->wait(th2));
  downstream->waitForDisconnect();
}

class ReceiveReversePortForwardButDoNotConfirm : public Task<void, Tasks::Channel> {
public:
  void start() override {
    callbacks_->setTimeout(default_timeout_, fmt::format("ReceiveReversePortForwardButDoNotConfirm"));
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelOpenMsg& open_msg) {
        return open_msg.request.visit(
          [&](const wire::ForwardedTcpipChannelOpenMsg&) {
            taskSuccess(Tasks::Channel{
              .local_id = 1,
              .remote_id = open_msg.sender_channel,
              .initial_window_size = open_msg.initial_window_size,
              .max_packet_size = open_msg.max_packet_size,
              .upstream_initial_window_size = wire::ChannelWindowSize,
              .upstream_max_packet_size = wire::ChannelMaxPacketSize,
            });
            return Break;
          },
          DEFAULT_CONTINUE);
      },
      DEFAULT_CONTINUE);
  }
};

TEST_P(StaticPortForwardTest, HostDrainBeforeInitializationClosesDownstreamConnections) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<ReceiveReversePortForwardButDoNotConfirm>()
                             .saveOutput(&channel)
                             .start()));

  setClusterLoad(cluster_name, {});
  auto th = driver->createTask<Tasks::WaitForChannelCloseByPeer>().start(channel);
  driver->sendMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = channel.remote_id,
    .sender_channel = channel.local_id,
    .initial_window_size = wire::ChannelWindowSize,
    .max_packet_size = wire::ChannelMaxPacketSize,
  });
  ASSERT_TRUE(driver->wait(th));

  downstream->waitForDisconnect();
}

TEST_P(StaticPortForwardTest, HostDrainBeforeChannelOpenFailureClosesDownstreamConnections) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::RejectReversePortForward>(route_name, route_port)
                             .start()));

  setClusterLoad(cluster_name, {});
  downstream->waitForDisconnect();
}

TEST_P(StaticPortForwardTest, DownstreamConnectWithNoHealthyUpstreams) {
  setClusterLoad(cluster_name, {});
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  downstream->waitForDisconnect();
}

TEST_P(StaticPortForwardTest, InternalDownstreamChannelOpenFails) {
  // The only way this fails is if the max concurrent channels limit has been reached.
  // The default limit for ssh integration tests is 100.
  std::deque<Tasks::Channel> channels;
  channels.resize(100);
  std::vector<IntegrationTcpClientPtr> downstreams;
  for (int i = 0; i < 100; i++) {
    downstreams.push_back(makeTcpConnectionWithServerName(route_port, route_name));
    ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, i)
                               .saveOutput(&channels[i])
                               .start()));
  }
  // 101st channel should fail to open
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  downstream->waitForDisconnect();

  for (auto& d : downstreams) {
    d->close(Network::ConnectionCloseType::AbortReset);
    ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForChannelCloseByPeer>()
                               .start(channels.front())));
    channels.pop_front();
  }
}

class ChannelCloseTimeoutTest : public Envoy::Event::TestUsingSimulatedTime,
                                public StaticPortForwardTest {
  using StaticPortForwardTest::StaticPortForwardTest;
};

TEST_P(ChannelCloseTimeoutTest, UpstreamIgnoresChannelCloseDuringHostDrain) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);
  Tasks::Channel channel;
  auto th = driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
              .saveOutput(&channel)
              .then(driver->createTask<Tasks::SendChannelData>("ping")
                      .then(driver->createTask<Tasks::WaitForChannelData>("pong")))
              .start();

  downstream->waitForData("ping");
  EXPECT_TRUE(downstream->write("pong"));
  ASSERT_TRUE(driver->wait(th));

  // Only receive the channel close message, but don't reply
  auto th2 = driver->createTask<Tasks::WaitForChannelMsg<wire::ChannelCloseMsg>>()
               .start(channel);
  setClusterLoad(cluster_name, {});
  ASSERT_TRUE(driver->wait(th2));
  simTime().advanceTimeWait(CloseResponseGracePeriod + std::chrono::milliseconds(10));
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::WaitForDisconnectWithError>("timed out waiting for channel close").start()));
  downstream->waitForDisconnect();
}

class DynamicPortForwardTest : public BaseReverseTunnelIntegrationTest,
                               public testing::WithParamInterface<Network::Address::IpVersion> {
public:
  DynamicPortForwardTest()
      : BaseReverseTunnelIntegrationTest(GetParam()) {}

  void SetUp() override {
    initialize();
    driver = makeSshConnectionDriver();
    RELEASE_ASSERT(driver->connectionDispatcher().ptr() == dispatcher_.get(), "");
    driver->connect();
    ASSERT_TRUE(driver->waitForKex());
    ASSERT_TRUE(driver->waitForUserAuth());
    ASSERT_TRUE(driver->requestReversePortForward("", 0, virtual_port));

    setClusterLoad(cluster_name,
                   {{
                     .stream_id = *driver->serverStreamId(),
                     .requested_host = "",
                     .requested_port = 0,
                     .server_port = virtual_port,
                     .is_dynamic = true,
                   }});
  }

  void TearDown() override {
    ASSERT_TRUE(driver->disconnect());
  }

  const uint32_t virtual_port = 12345;
  const std::string cluster_name = "tcp_cluster";
  std::shared_ptr<SshConnectionDriver> driver;
};

class DoSocks5ServerHandshake : public Task<Tasks::Channel, Tasks::Channel> {
public:
  DoSocks5ServerHandshake(Network::Address::IpVersion version) {
    if (version == Network::Address::IpVersion::v4) {
      expected_buffer_ = "\x05\x01\x00"
                         "\x05\x01\x00\x01"
                         "\x7F\x00\x00\x01" // 127.0.0.1
                         "\x01\xBB"sv;      // 443
    } else {
      expected_buffer_ = "\x05\x01\x00"
                         "\x05\x01\x00\x04"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" // ::1
                         "\x01\xBB"sv;                                                      // 443
    }
  }
  void start(Tasks::Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_, "DoSocks5ServerHandshake");
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{0x05, 0x00},
    });
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{0x05, 0x00, 0x00, 0x01,
                    0, 0, 0, 0, // 0.0.0.0
                    0, 0},      // 0
    });
  }

  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::ChannelDataMsg& msg) {
        received_buffer_.append_range(*msg.data);
        if (received_buffer_ == expected_buffer_) {
          taskSuccess(channel_);
        } else if (!expected_buffer_.starts_with(received_buffer_)) {
          taskFailure(absl::InternalError(fmt::format("socks5 handshake bytes mismatch: expected: {}, received: {}",
                                                      expected_buffer_, received_buffer_)));
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }

  std::string received_buffer_;

  // this address comes from buildStaticCluster("tcp_cluster", 443, localhost)
  // in the SshIntegrationTest constructor
  std::string_view expected_buffer_;
  Tasks::Channel channel_;
};

TEST_P(DynamicPortForwardTest, DynamicPortForward) {
  auto downstream = makeTcpConnectionWithServerName(lookupPort("tcp"), "tcp-cluster");

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>("", virtual_port, 1)
                             .saveOutput(&channel)
                             .then(driver->createTask<DoSocks5ServerHandshake>(version_))
                             .start()));

  auto th = driver->createTask<Tasks::SendChannelData>("ping")
              .then(driver->createTask<Tasks::WaitForChannelData>("pong")
                      .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))
              .start(channel);

  downstream->waitForData("ping");
  EXPECT_TRUE(downstream->write("pong"));

  downstream->waitForDisconnect();
  downstream->close();
}

class ConflictingModesPortForwardTest : public BaseReverseTunnelIntegrationTest,
                                        public testing::WithParamInterface<std::tuple<Network::Address::IpVersion, std::string>> {
public:
  ConflictingModesPortForwardTest()
      : BaseReverseTunnelIntegrationTest(std::get<0>(GetParam())),
        requested_host_(std::get<1>(GetParam())) {}

  void SetUp() override {
    initialize();
    driver = makeSshConnectionDriver();
    driver->connect();
    ASSERT_TRUE(driver->waitForKex());
    ASSERT_TRUE(driver->waitForUserAuth());
    ASSERT_TRUE(driver->requestReversePortForward(requested_host_, 0, virtual_port));

    setClusterLoad(cluster_name,
                   {{
                     .stream_id = *driver->serverStreamId(),
                     .requested_host = requested_host_,
                     .requested_port = 0,
                     .server_port = virtual_port,
                     .is_dynamic = false, // <- envoy thinks the upstream is not expecting dynamic mode
                   }});
  }

  void TearDown() override {
    ASSERT_TRUE(driver->disconnect());
  }

  const uint32_t virtual_port = 12345;
  const std::string cluster_name = "tcp_cluster";
  const std::string requested_host_;
  std::shared_ptr<SshConnectionDriver> driver;
};

TEST_P(ConflictingModesPortForwardTest, UpstreamExpectingDynamicMode) {
  auto downstream = makeTcpConnectionWithServerName(lookupPort("tcp"), "tcp-cluster");

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(driver->createTask<Tasks::AcceptReversePortForward>(requested_host_, virtual_port, 1)
                             .saveOutput(&channel)
                             .start()));

  // mimic openssh server behavior
  auto th = driver->createTask<Tasks::WaitForChannelData>("not a socks5 handshake")
              .then(driver->createTask<Tasks::SendChannelCloseAndWait>(Tasks::SendEOF(true)))
              .start(channel);

  EXPECT_TRUE(downstream->write("not a socks5 handshake"));
  ASSERT_TRUE(driver->wait(th));
  EXPECT_TRUE(driver->waitForDiagnostic("ssh client may be expecting dynamic port-forwarding"));

  downstream->waitForDisconnect();
  downstream->close();
}

class DoSocks5ServerHandshakeWithExtraData : public DoSocks5ServerHandshake {
public:
  using DoSocks5ServerHandshake::DoSocks5ServerHandshake;
  void start(Tasks::Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_, "DoSocks5ServerHandshakeWithExtraData");
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{0x05, 0x00},
    });
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = bytes{0x05, 0x00, 0x00, 0x01,
                    0, 0, 0, 0, // 0.0.0.0
                    0, 0,       // 0
                    'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'},
    });
  }
};

TEST_P(DynamicPortForwardTest, Socks5HandshakeMoreDataAfterHandshakeComplete) {
  auto downstream = makeTcpConnectionWithServerName(lookupPort("tcp"), "tcp-cluster");

  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>("", virtual_port, 1)
      .then(driver->createTask<DoSocks5ServerHandshakeWithExtraData>(version_)
              .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))
      .start()));

  downstream->waitForData("hello world");
  downstream->waitForDisconnect();
  downstream->close();
}

TEST_P(DynamicPortForwardTest, Socks5HandshakeError) {
  auto downstream = makeTcpConnectionWithServerName(lookupPort("tcp"), "tcp-cluster");

  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>("", virtual_port, 1)
      .then(driver->createTask<Tasks::WaitForChannelData>("\x05\x01\x00"s)
              .then(driver->createTask<Tasks::WaitForChannelCloseByPeer>(Tasks::ExpectEOF(true))) // in parallel
              .then(driver->createTask<Tasks::SendChannelData>("\x04\x00"_bytes)))                //
      .start()));

  downstream->waitForDisconnect();
  downstream->close();
}

class EDSUpdatesIntegrationTest : public BaseReverseTunnelIntegrationTest,
                                  public testing::WithParamInterface<std::tuple<Network::Address::IpVersion, std::string>> {
public:
  EDSUpdatesIntegrationTest()
      : BaseReverseTunnelIntegrationTest(std::get<0>(GetParam())) {
    config_helper_.addRuntimeOverride(
      "envoy.reloadable_features.xdstp_based_config_singleton_subscriptions",
      std::get<1>(GetParam()));
  }
};

TEST_P(EDSUpdatesIntegrationTest, TestClusterUpdates) {
  initialize();
  const auto tcpPort = lookupPort("tcp");

  ClusterLoadOpts endpoint1{
    .stream_id = 1,
    .requested_host = "tcp-cluster",
    .requested_port = tcpPort,
    .server_port = tcpPort,
    .is_dynamic = false,
  };
  setClusterLoad("tcp_cluster", {endpoint1});

  test_server_->waitForCounterEq("cluster.tcp_cluster.update_no_rebuild", 0, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_total", 1, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_healthy", 1, std::chrono::seconds(1));
  test_server_->waitForCounterEq("cluster.tcp_cluster.membership_change", 1, std::chrono::seconds(1));

  ClusterLoadOpts endpoint2{
    .stream_id = 2,
    .requested_host = "",
    .requested_port = 0,
    .server_port = 10000,
    .is_dynamic = true,
  };
  setClusterLoad("tcp_cluster", {endpoint1, endpoint2});

  test_server_->waitForCounterEq("cluster.tcp_cluster.update_no_rebuild", 0, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_total", 2, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_healthy", 2, std::chrono::seconds(1));
  test_server_->waitForCounterEq("cluster.tcp_cluster.membership_change", 2, std::chrono::seconds(1));

  ClusterLoadOpts endpoint3{
    .stream_id = 3,
    .requested_host = "localhost",
    .requested_port = 0,
    .server_port = 10000,
    .is_dynamic = true,
  };
  setClusterLoad("tcp_cluster", {endpoint1, endpoint2, endpoint3});

  test_server_->waitForCounterEq("cluster.tcp_cluster.update_no_rebuild", 0, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_total", 3, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_healthy", 3, std::chrono::seconds(1));
  test_server_->waitForCounterEq("cluster.tcp_cluster.membership_change", 3, std::chrono::seconds(1));

  setClusterLoad("tcp_cluster", {endpoint2, endpoint3});

  test_server_->waitForCounterEq("cluster.tcp_cluster.update_no_rebuild", 0, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_total", 2, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_healthy", 2, std::chrono::seconds(1));
  test_server_->waitForCounterEq("cluster.tcp_cluster.membership_change", 4, std::chrono::seconds(1));

  endpoint3.is_dynamic = false; // trigger metadata update
  setClusterLoad("tcp_cluster", {endpoint2, endpoint3});

  test_server_->waitForCounterEq("cluster.tcp_cluster.update_no_rebuild", 0, std::chrono::seconds(1)); // <-
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_total", 2, std::chrono::seconds(1));
  test_server_->waitForGaugeEq("cluster.tcp_cluster.membership_healthy", 2, std::chrono::seconds(1));
  test_server_->waitForCounterEq("cluster.tcp_cluster.membership_change", 4, std::chrono::seconds(1));
}

TEST_P(EDSUpdatesIntegrationTest, WrongClusterName) {
  initialize();

  envoy::config::endpoint::v3::ClusterLoadAssignment load;
  load.set_cluster_name("http_cluster");
  eds_helpers_["tcp_cluster"]->setEds(load);
  test_server_->waitForCounterEq("cluster.tcp_cluster.update_rejected", 1, std::chrono::seconds(1));
}

TEST_P(EDSUpdatesIntegrationTest, InvalidResourceCount) {
  initialize();

  // from setEdsAndWait
  envoy::config::endpoint::v3::ClusterLoadAssignment load;
  load.set_cluster_name("tcp_cluster");
  envoy::service::discovery::v3::DiscoveryResponse eds_response;
  eds_response.set_version_info("1");
  eds_response.set_type_url(Config::TestTypeUrl::get().ClusterLoadAssignment);
  eds_response.add_resources()->PackFrom(load);
  eds_response.add_resources()->PackFrom(load); // <- more than 1 resource

  std::string path = TestEnvironment::writeStringToFileForTest(
    "tcp_cluster_eds.update.pb_text", MessageUtil::toTextProto(eds_response));
  TestEnvironment::renameFile(path, absl::StrReplaceAll(path, {{".update"s, ""s}}));

  test_server_->waitForCounterEq("cluster.tcp_cluster.update_failure", 1, std::chrono::seconds(1));
}

TEST_P(EDSUpdatesIntegrationTest, InvalidResourceData) {
  initialize();

  std::string path = TestEnvironment::writeStringToFileForTest(
    "tcp_cluster_eds.update.pb_text", "bad data");
  TestEnvironment::renameFile(path, absl::StrReplaceAll(path, {{".update"s, ""s}}));
  test_server_->waitForCounterGe("cluster.tcp_cluster.update_failure", 1, std::chrono::seconds(1));
}

TEST_P(EDSUpdatesIntegrationTest, InvalidLbEndpointName) {
  initialize();

  int num_failures = 0;
  for (auto name : {"invalid endpoint name", "ssh:", "ssh:not a number"}) {
    envoy::config::endpoint::v3::ClusterLoadAssignment load;
    load.set_cluster_name("tcp_cluster");
    auto* endpoint = load.add_endpoints()->add_lb_endpoints();
    auto* socketAddress = endpoint->mutable_endpoint()->mutable_address()->mutable_socket_address();
    socketAddress->set_address(name);
    socketAddress->set_port_value(12345);

    envoy::service::discovery::v3::DiscoveryResponse eds_response;
    eds_response.set_version_info(std::to_string(num_failures));
    eds_response.set_type_url(Config::TestTypeUrl::get().ClusterLoadAssignment);
    eds_response.add_resources()->PackFrom(load);

    std::string path = TestEnvironment::writeStringToFileForTest(
      "tcp_cluster_eds.update.pb_text", MessageUtil::toTextProto(eds_response));
    TestEnvironment::renameFile(path, absl::StrReplaceAll(path, {{".update"s, ""s}}));

    test_server_->waitForCounterEq("cluster.tcp_cluster.update_failure", ++num_failures, std::chrono::seconds(1));
  }
}

TEST_P(EDSUpdatesIntegrationTest, InvalidClusterEDSConfig) {
  config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    bootstrap.mutable_static_resources()->mutable_clusters(3)->clear_eds_cluster_config();
  });
  initialize();
}

class ChannelStatsIntegrationTest : public Envoy::Event::TestUsingSimulatedTime,
                                    public StaticPortForwardTest {
public:
  using StaticPortForwardTest::StaticPortForwardTest;
};

TEST_P(ChannelStatsIntegrationTest, TestPeriodicEvents) {
  auto downstream = makeTcpConnectionWithServerName(route_port, route_name);

  Tasks::Channel channel;
  ASSERT_TRUE(driver->wait(
    driver->createTask<Tasks::AcceptReversePortForward>(route_name, route_port, 1)
      .saveOutput(&channel)
      .start()));

  auto th = driver->createTask<Tasks::WaitForChannelData>("response")
              .then(driver->createTask<Tasks::SendChannelData>("request"))
              .start(channel);
  EXPECT_TRUE(downstream->write("response"));
  downstream->waitForData("request");
  ASSERT_TRUE(driver->wait(th));

  // FIXME: definitely doing something wrong here. This should be using advanceTimeWait() to
  // process timers on all threads, but it blocks, and I can't figure out why. We need to wait for
  // the worker thread to run the timer, so sleeping here is a temporary workaround.
  simTime().advanceTimeAndRun(std::chrono::milliseconds(6000), *dispatcher_,
                              Envoy::Event::Dispatcher::RunType::NonBlock);
  timeSystem().realSleepDoNotUseWithoutScrutiny(std::chrono::milliseconds(10));

  pomerium::extensions::ssh::ChannelStatsList stats;
  ASSERT_TRUE(driver->waitForStatsEvent(&stats));
  // EXPECT_THAT(DurationUtil::durationToMilliseconds(stats.channel_duration()), testing::Ge(5000 * (i + 1))); // TODO
  EXPECT_EQ(1, stats.items_size());
  EXPECT_EQ(100, stats.items(0).channel_id());
  EXPECT_EQ(7, stats.items(0).tx_bytes_total());
  EXPECT_EQ(8, stats.items(0).rx_bytes_total());
  EXPECT_TRUE(stats.items(0).has_start_time());

  auto th2 = driver->createTask<Tasks::WaitForChannelData>("response")
               .then(driver->createTask<Tasks::SendChannelData>("request"))
               .start(channel);
  EXPECT_TRUE(downstream->write("response"));
  downstream->waitForData("request");
  ASSERT_TRUE(driver->wait(th2));

  // simTime().advanceTimeAndRun(std::chrono::milliseconds(6000), *dispatcher_,
  //                             Envoy::Event::Dispatcher::RunType::NonBlock);
  // timeSystem().realSleepDoNotUseWithoutScrutiny(std::chrono::milliseconds(10));

  // pomerium::extensions::ssh::ChannelStats stats2;
  // ASSERT_TRUE(driver->waitForStatsEvent(&stats2));
  // // EXPECT_THAT(DurationUtil::durationToMilliseconds(stats.channel_duration()), testing::Ge(5000 * (i + 1))); // TODO
  // EXPECT_EQ(14, stats2.tx_bytes_total());
  // EXPECT_EQ(16, stats2.rx_bytes_total());

  auto th3 = driver->createTask<Tasks::SendChannelCloseAndWait>().start(channel);
  downstream->waitForDisconnect();
  ASSERT_TRUE(driver->wait(th3));
  pomerium::extensions::ssh::ChannelStats close_stats;
  ASSERT_TRUE(driver->waitForStatsOnChannelClose(&close_stats));
  // EXPECT_THAT(DurationUtil::durationToMilliseconds(close_stats.channel_duration()), testing::Ge(5000 * iterations)); // TODO
  EXPECT_EQ(14, close_stats.tx_bytes_total());
  EXPECT_EQ(16, close_stats.rx_bytes_total());

  downstream->close();
}

INSTANTIATE_TEST_SUITE_P(HttpReverseTunnel, HttpReverseTunnelIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

INSTANTIATE_TEST_SUITE_P(StaticPortForward, StaticPortForwardTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

INSTANTIATE_TEST_SUITE_P(StaticPortForwardWithHalfClose, StaticPortForwardWithHalfCloseTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

INSTANTIATE_TEST_SUITE_P(DynamicPortForward, DynamicPortForwardTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

INSTANTIATE_TEST_SUITE_P(ConflictingModes, ConflictingModesPortForwardTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                                          testing::ValuesIn({""s, "localhost"s, "*"s, "*-cluster"s, "tcp?cluster"s})));

INSTANTIATE_TEST_SUITE_P(EDSUpdates, EDSUpdatesIntegrationTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                                          testing::ValuesIn({"false"s, "true"s})));

INSTANTIATE_TEST_SUITE_P(ChannelStats, ChannelStatsIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

INSTANTIATE_TEST_SUITE_P(ChannelCloseTimeout, ChannelCloseTimeoutTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

class SshReverseTunnelClusterUnitTest : public testing::Test {
public:
  envoy::config::cluster::v3::Cluster buildClusterConfig() {
    auto cluster = ConfigHelper::buildStaticCluster("test_cluster", 443, "localhost");
    cluster.clear_upstream_bind_config();
    cluster.clear_type();

    envoy::extensions::transport_sockets::internal_upstream::v3::InternalUpstreamTransport internal_upstream;

    envoy::extensions::transport_sockets::raw_buffer::v3::RawBuffer raw_buffer;
    internal_upstream.mutable_transport_socket()->set_name("envoy.transport_sockets.raw_buffer");
    internal_upstream.mutable_transport_socket()->mutable_typed_config()->PackFrom(raw_buffer);

    cluster.mutable_transport_socket()->set_name("envoy.transport_sockets.internal_upstream");
    cluster.mutable_transport_socket()->mutable_typed_config()->PackFrom(internal_upstream);

    pomerium::extensions::ssh::ReverseTunnelCluster reverse_tunnel_cluster;
    reverse_tunnel_cluster.set_name(cluster.name());
    reverse_tunnel_cluster.mutable_eds_config()->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
    reverse_tunnel_cluster.mutable_eds_config()->mutable_ads();
    cluster.mutable_cluster_type()->set_name("envoy.clusters.ssh_reverse_tunnel");
    cluster.mutable_cluster_type()->mutable_typed_config()->PackFrom(reverse_tunnel_cluster);

    return cluster;
  }

  Envoy::Upstream::ClusterFactory* getFactory() {
    auto* f = Registry::FactoryRegistry<Upstream::ClusterFactory>::getFactory("envoy.clusters.ssh_reverse_tunnel");
    RELEASE_ASSERT(f != nullptr, "");
    return f;
  }

  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  Envoy::Upstream::ClusterFactoryContextImpl cluster_context_{context_, nullptr, nullptr, false};
};

TEST_F(SshReverseTunnelClusterUnitTest, ErrorCreatingCluster) {
  auto cluster = buildClusterConfig();

  EXPECT_CALL(context_.cluster_manager_.subscription_factory_, subscriptionFromConfigSource)
    .WillOnce(Return(absl::InternalError("test error")));

  auto* factory = getFactory();
  Envoy::Upstream::ClusterFactoryContextImpl cluster_context(context_, nullptr, nullptr, false);
  auto res = factory->create(cluster, cluster_context);
  EXPECT_EQ(absl::InternalError("test error"), res.status());
}

TEST_F(SshReverseTunnelClusterUnitTest, ConfigUpdateFailed) {
  auto cluster = buildClusterConfig();

  auto res = getFactory()->create(cluster, cluster_context_);
  ASSERT_OK(res);
  auto reverseTunnelCluster = std::dynamic_pointer_cast<Upstream::SshReverseTunnelCluster>(std::move(res).value().first);
  reverseTunnelCluster->initialize([] { return absl::OkStatus(); });

  reverseTunnelCluster->onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason::ConnectionFailure, nullptr);
  EXPECT_EQ(1, context_.store_.counter("cluster.test_cluster.update_failure").value());
  reverseTunnelCluster->onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason::FetchTimedout, nullptr);
  EXPECT_EQ(2, context_.store_.counter("cluster.test_cluster.update_failure").value());

  EnvoyException fake("fake exception");
  reverseTunnelCluster->onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason::UpdateRejected, &fake);
  EXPECT_EQ(3, context_.store_.counter("cluster.test_cluster.update_failure").value());
}

TEST_F(SshReverseTunnelClusterUnitTest, DeltaXdsConfigUpdate) {
  auto cluster = buildClusterConfig();
  auto res = getFactory()->create(cluster, cluster_context_);
  ASSERT_OK(res);
  auto reverseTunnelCluster = std::dynamic_pointer_cast<Upstream::SshReverseTunnelCluster>(std::move(res).value().first);
  reverseTunnelCluster->initialize([] { return absl::OkStatus(); });

  Protobuf::RepeatedPtrField<envoy::service::discovery::v3::Resource> resources;
  auto* resource = resources.Add();
  envoy::config::endpoint::v3::ClusterLoadAssignment cluster_load_assignment;
  cluster_load_assignment.set_cluster_name("test_cluster");
  resource->mutable_resource()->PackFrom(cluster_load_assignment);
  const auto decoded_resources =
    TestUtility::decodeResources<envoy::config::endpoint::v3::ClusterLoadAssignment>(
      resources, "cluster_name");
  ASSERT_OK(reverseTunnelCluster->onConfigUpdate(decoded_resources.refvec_, {}, "v1"));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec