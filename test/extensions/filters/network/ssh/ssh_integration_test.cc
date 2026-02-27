#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.h"
#include "envoy/extensions/transport_sockets/internal_upstream/v3/internal_upstream.pb.h"
#include "test/extensions/filters/network/ssh/ssh_upstream.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

SshIntegrationTest::SshIntegrationTest(std::vector<std::string> ssh_routes, Network::Address::IpVersion version)
    : HttpIntegrationTest(Http::CodecType::HTTP1, version, defaultConfig(ssh_routes, version)) {
  fake_upstreams_count_ = 0; // add our upstreams manually
  config_helper_.addConfigModifier([this, localhost = localhost(), ssh_routes](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    RELEASE_ASSERT(bootstrap.mutable_static_resources()->clusters_size() == 0, "");
    auto fakeMgmtCluster = ConfigHelper::buildStaticCluster("fake_mgmt", 0, localhost);
    ConfigHelper::setHttp2(fakeMgmtCluster);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(fakeMgmtCluster);

    // Upstream bug: BaseIntegrationTest::createEnvoy() does not assign ports in the correct order
    // unless all fake upstreams which use dynamic ports are ordered before fake upstreams that use
    // custom clusters
    for (const auto& route : ssh_routes) {
      auto c = ConfigHelper::buildStaticCluster("ssh_upstream_" + route, 0, localhost);
      bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(c);
    }

    ConfigHelper::HttpProtocolOptions http1_protocol_options;
    http1_protocol_options.mutable_explicit_http_config()->clear_http2_protocol_options();
    http1_protocol_options.mutable_explicit_http_config()->mutable_http_protocol_options();
    http1_protocol_options.mutable_common_http_protocol_options()->mutable_max_requests_per_connection()->set_value(1);

    auto httpCluster1 = ConfigHelper::buildStaticCluster("http_cluster_1", 443, localhost);
    ConfigHelper::setProtocolOptions(httpCluster1, http1_protocol_options);
    configureUpstreamTunnelCluster(httpCluster1);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(httpCluster1);

    auto httpCluster2 = ConfigHelper::buildStaticCluster("http_cluster_2", 443, localhost);
    ConfigHelper::setHttp2(httpCluster2);
    configureUpstreamTunnelCluster(httpCluster2);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(httpCluster2);

    auto tcpCluster = ConfigHelper::buildStaticCluster("tcp_cluster", 443, localhost);
    tcpCluster.clear_typed_extension_protocol_options();
    configureUpstreamTunnelCluster(tcpCluster);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(tcpCluster);
  });
  mgmt_upstream_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP2, "mgmt_upstream")};
  for (size_t i = 0; i < ssh_routes.size(); i++) {
    ssh_upstreams_.emplace_back(&addFakeUpstream(Http::CodecType::HTTP1, "ssh_upstream_" + ssh_routes[i])); // codec type is unused here
  }
  http_upstream_1_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP1, "http_upstream_1")};
  http_upstream_2_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP1, "http_upstream_2")};
  tcp_upstream_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP1, "tcp_upstream")}; // codec type is unused here
}

SshIntegrationTest::~SshIntegrationTest() = default;

void SshIntegrationTest::cleanup() {
  for (auto& upstream : ssh_upstreams_) {
    upstream.cleanup();
  }
};

void FakeUpstreamShimImpl::cleanup() {
  if (handler_ != nullptr) {
    absl::Notification done;
    fake_upstream_->dispatcher()->post([handler = std::move(handler_), &done] mutable {
      handler.reset();
      done.Notify();
    });
    done.WaitForNotification();
  }
  fake_upstream_->cleanUp();
}

void SshIntegrationTest::initialize() {
  HttpIntegrationTest::initialize();
  registerTestServerPorts({"http", "ssh", "tcp"});
}
std::shared_ptr<SshConnectionDriver> SshIntegrationTest::makeSshConnectionDriver() {
  return std::make_shared<SshConnectionDriver>(
    makeClientConnection(lookupPort("ssh")),
    server_factory_context_,
    std::make_shared<pomerium::extensions::ssh::CodecConfig>(),
    mgmt_upstream_);
}

AssertionResult SshIntegrationTest::configureSshUpstream(SshFakeUpstreamHandlerOpts&& opts, size_t upstream_index) {
  ASSERT(upstream_index < ssh_upstreams_.size());
  return ssh_upstreams_[upstream_index].configureSshUpstream(
    std::make_shared<SshFakeUpstreamHandlerOpts>(std::move(opts)), server_factory_context_);
}

void SshIntegrationTest::configureUpstreamTunnelCluster(envoy::config::cluster::v3::Cluster& cluster) {
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

void SshIntegrationTest::setClusterLoad(const std::string& cluster_name, std::vector<ClusterLoadOpts> endpoint_opts) {
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

AssertionResult FakeUpstreamShimImpl::waitForHttpConnection(Envoy::Event::Dispatcher& client_dispatcher,
                                                            std::unique_ptr<FakeHttpConnectionShim>& connection,
                                                            std::chrono::milliseconds timeout) {
  std::unique_ptr<FakeHttpConnection> real;
  auto ret = fake_upstream_->waitForHttpConnection(client_dispatcher, real, timeout);
  connection = std::make_unique<FakeHttpConnectionShimImpl>(std::move(real));
  return ret;
}

AssertionResult FakeUpstreamShimImpl::configureSshUpstream(std::shared_ptr<SshFakeUpstreamHandlerOpts> opts,
                                                           Server::Configuration::ServerFactoryContext& server_factory_context) {
  // FakeUpstream isn't really built to do what we need here, which is to have it pre-configured
  // with callbacks that all run on its own thread. We don't want to drive it from the test thread,
  // because we are already driving the downstream connection from the test thread. The tests need
  // to be able to block and wait for the downstream to complete user auth, but part of that
  // sequence involves connecting to the upstream, which would otherwise need to be a separate
  // blocking operation on the test thread.
  return fake_upstream_->runOnDispatcherThreadAndWait([this, opts, ctx = &server_factory_context] {
    ASSERT(timer_ == nullptr);
    // XXX: this only handles one connection. If we need to support multiple upstream connections at
    // the same time, this will need to be adjusted.
    ASSERT(handler_ == nullptr);
    handler_ = std::make_unique<SshFakeUpstreamHandler>(
      *ctx,
      std::make_shared<pomerium::extensions::ssh::CodecConfig>(),
      opts);
    timer_ = fake_upstream_->dispatcher()->createTimer([this] {
      absl::ReleasableMutexLock lock(fake_upstream_->lock());
      if (!fake_upstream_->hasNewConnections()) {
        timer_->enableTimer(std::chrono::milliseconds(10));
        return;
      }
      timer_ = nullptr;
      auto& sc = fake_upstream_->consumeConnection();
      lock.Release();
      handler_->onNewConnection(sc.connection());
    });
    timer_->enableTimer(std::chrono::milliseconds(10));
    return testing::AssertionSuccess();
  });
}

std::string SshIntegrationTest::defaultConfig(const std::vector<std::string>& routes, Network::Address::IpVersion version) {
  // TODO: we should relax this restriction
  RELEASE_ASSERT(!routes.empty(), "must set at least one route for the ssh listener to activate");
  constexpr auto baseConfigFmt = R"(
admin:
  access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: "/dev/null"
  address:
    socket_address:
      address: "{}"
      port_value: 0
dynamic_resources:
  lds_config:
    path_config_source:
      path: /dev/null
static_resources:
  secrets:
  - name: "secret_static_0"
    tls_certificate:
      certificate_chain:
        inline_string: "DUMMY_INLINE_BYTES"
      private_key:
        inline_string: "DUMMY_INLINE_BYTES"
      password:
        inline_string: "DUMMY_INLINE_BYTES"
  listeners:
)";
  constexpr auto httpListenerFmt = R"(
  - name: http
    address:
      socket_address:
        address: "{}"
        port_value: 0
    filter_chains:
      filters:
        name: http
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
          delayed_close_timeout:
            nanos: 10000000
          http_filters:
            - name: envoy.filters.http.set_filter_state
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
                on_request_headers:
                  - object_key: pomerium.extensions.ssh.downstream_source_address
                    format_string:
                      text_format_source:
                        inline_string: '%DOWNSTREAM_REMOTE_ADDRESS%'
                    shared_with_upstream: ONCE
                  - object_key: pomerium.extensions.ssh.requested_server_name
                    format_string:
                      text_format_source:
                        inline_string: '%REQUESTED_SERVER_NAME%'
                    shared_with_upstream: ONCE
                  - object_key: pomerium.extensions.ssh.requested_path
                    format_string:
                      text_format_source:
                        inline_string: '%PATH(NQ)%'
                    shared_with_upstream: ONCE
            - name: envoy.filters.http.router
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          codec_type: HTTP1
          access_log:
            name: accesslog
            filter:
              not_health_check_filter:  {{}}
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: /dev/null
          route_config:
            name: http_routes
            virtual_hosts:
              - name: http_cluster_1
                domains:
                  - http-cluster-1
                routes:
                  - route:
                      cluster: http_cluster_1
                    match:
                      prefix: "/"
              - name: http_cluster_2
                domains:
                  - http-cluster-2
                routes:
                  - route:
                      cluster: http_cluster_2
                    match:
                      prefix: "/"
)";
  constexpr auto sshListenerFmt = R"(
  - name: ssh
    address:
      socket_address:
        address: "{}"
        port_value: 0
    filter_chains:
    - filters:
      - name: generic_proxy
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.v3.GenericProxy
          stat_prefix: ssh
          codec_config:
            name: envoy.generic_proxy.codecs.ssh
            typed_config:
              '@type': type.googleapis.com/pomerium.extensions.ssh.CodecConfig
              host_keys:
                - inline_string: "{}"
              user_ca_key:
                inline_string: "{}"
              grpc_service:
                envoy_grpc:
                  cluster_name: fake_mgmt
                timeout: 0s
              max_concurrent_channels: 100
              internal_channel_id_start: 100
          filters:
            - name: envoy.filters.generic.router
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.router.v3.Router
                bind_upstream_connection: true
          route_config:
            name: route_config
            virtual_hosts:
              - name: ssh
                hosts:
                  - '*'
                routes:
                  matcher_list:
                    matchers: {}
)";
  constexpr auto matcherTemplate = R"(
                      - predicate:
                          single_predicate:
                            input:
                              name: request
                              typed_config:
                                '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatchInput
                            custom_match:
                              name: request
                              typed_config:
                                '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatcher
                                host:
                                  exact: "{}"
                        on_match:
                          action:
                            name: route
                            typed_config:
                              '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.action.v3.RouteAction
                              cluster: "{}"
                              timeout: 0s
)";
  constexpr auto tcpListenerFmt = R"(
  - name: tcp
    address:
      socket_address:
        address: "{}"
        port_value: 0
    listener_filters:
    - name: test.integration.server_name_injector
      typed_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
    filter_chains:
      filters:
      - name: envoy.filters.network.set_filter_state
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.set_filter_state.v3.Config
          on_new_connection:
          - object_key: pomerium.extensions.ssh.requested_server_name
            format_string:
              text_format_source:
                inline_string: '%REQUESTED_SERVER_NAME%'
            shared_with_upstream: ONCE
          - object_key: pomerium.extensions.ssh.downstream_source_address
            format_string:
              text_format_source:
                inline_string: '%DOWNSTREAM_REMOTE_ADDRESS%'
            shared_with_upstream: ONCE
      - name: tcp
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcpproxy_stats
          cluster: tcp_cluster
)";
  std::string matchers;
  for (const auto& route : routes) {
    matchers += fmt::format(matcherTemplate, route, "ssh_upstream_" + route);
  }
  auto lh = localhost(version);
  const auto baseConfig = fmt::format(baseConfigFmt, lh);
  const auto httpListener = fmt::format(httpListenerFmt, lh);
  const auto sshListener = fmt::format(sshListenerFmt,
                                       lh,
                                       *host_key_->formatPrivateKey(SSHKEY_PRIVATE_OPENSSH, true),
                                       *user_ca_key_->formatPrivateKey(SSHKEY_PRIVATE_OPENSSH, true),
                                       matchers);
  const auto tcpListener = fmt::format(tcpListenerFmt, lh);

  return absl::StrCat(baseConfig, httpListener, sshListener, tcpListener);
}

IntegrationTcpClientPtr SshIntegrationTest::makeTcpConnectionWithServerName(uint32_t port, const std::string& server_name) {
  auto tcp_client = makeTcpConnection(port, {}, {}, {});

  uint32_t len = ntohl(server_name.size());
  std::string len_str(reinterpret_cast<char*>(&len), sizeof(len));
  auto stat = tcp_client->write(len_str + server_name);
  EXPECT_TRUE(stat) << "failed to write server name to ServerNameInjector";
  return tcp_client;
}

class ServerNameInjector : public Network::ListenerFilter, public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override {
    callbacks_ = &cb;
    return Network::FilterStatus::StopIteration;
  }

  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override {
    if (buffer.rawSlice().len_ < read_bytes_) {
      return Network::FilterStatus::StopIteration;
    }
    if (!size_read_) {
      read_bytes_ = ntohl(*reinterpret_cast<const uint32_t*>(buffer.rawSlice().mem_));
      RELEASE_ASSERT(read_bytes_ <= 255, fmt::format("test bug: corrupted data read from socket "
                                                     "(read length field with value {})",
                                                     read_bytes_));
      buffer.drain(4);
      size_read_ = true;
      return Network::FilterStatus::StopIteration;
    }
    std::string name(reinterpret_cast<const char*>(buffer.rawSlice().mem_), read_bytes_);
    callbacks_->socket().setRequestedServerName(name);
    buffer.drain(read_bytes_);
    ENVOY_LOG(debug, "server name injected: {}", name);
    return Network::FilterStatus::Continue;
  }
  size_t maxReadBytes() const override {
    return read_bytes_;
  }

private:
  bool size_read_{};
  uint32_t read_bytes_{4};
  Network::ListenerFilterCallbacks* callbacks_;
};

class ServerNameInjectorConfigFactory : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
    const Protobuf::Message&,
    const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
    Server::Configuration::ListenerFactoryContext&) override {
    return [listener_filter_matcher](Network::ListenerFilterManager& filter_manager) -> void {
      filter_manager.addAcceptFilter(
        listener_filter_matcher, std::make_unique<ServerNameInjector>());
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Protobuf::StringValue>();
  }

  std::string name() const override { return "test.integration.server_name_injector"; }
};

REGISTER_FACTORY(ServerNameInjectorConfigFactory,
                 Server::Configuration::NamedListenerFilterConfigFactory);

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec