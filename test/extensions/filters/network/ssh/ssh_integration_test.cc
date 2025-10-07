#include "test/extensions/filters/network/ssh/ssh_integration_test.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

SshIntegrationTest::SshIntegrationTest(std::vector<std::string> ssh_routes, Network::Address::IpVersion version)
    : HttpIntegrationTest(Http::CodecType::HTTP1, version, defaultConfig(ssh_routes)) {
  fake_upstreams_count_ = 0; // add our upstreams manually
  config_helper_.addConfigModifier([localhost = localhost(), ssh_routes](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    ASSERT(bootstrap.mutable_static_resources()->clusters_size() == 0);
    auto fakeMgmtCluster = ConfigHelper::buildStaticCluster("fake_mgmt", 0, localhost);
    ConfigHelper::setHttp2(fakeMgmtCluster);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(fakeMgmtCluster);

    ConfigHelper::HttpProtocolOptions http1_protocol_options;
    http1_protocol_options.mutable_explicit_http_config()->clear_http2_protocol_options();
    http1_protocol_options.mutable_explicit_http_config()->mutable_http_protocol_options();

    auto httpCluster1 = ConfigHelper::buildStaticCluster("http_cluster_1", 0, localhost);
    ConfigHelper::setProtocolOptions(httpCluster1, http1_protocol_options);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(httpCluster1);

    auto httpCluster2 = ConfigHelper::buildStaticCluster("http_cluster_2", 0, localhost);
    ConfigHelper::setHttp2(httpCluster2);
    bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(httpCluster2);

    for (const auto& route : ssh_routes) {
      auto c = ConfigHelper::buildStaticCluster("ssh_upstream_" + route, 0, localhost);
      bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(c);
    }
  });
  mgmt_upstream_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP2)};
  http_upstream_1_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP1)};
  http_upstream_2_ = FakeUpstreamShimImpl{&addFakeUpstream(Http::CodecType::HTTP1)};
  for (size_t i = 0; i < ssh_routes.size(); i++) {
    ssh_upstreams_.emplace_back(&addFakeUpstream(Http::CodecType::HTTP1)); // codec type is unused here
  }
}

SshIntegrationTest::~SshIntegrationTest() {};

void SshIntegrationTest::initialize() {
  HttpIntegrationTest::initialize();
  registerTestServerPorts({"http", "ssh"});
}
std::shared_ptr<SshConnectionDriver> SshIntegrationTest::makeSshConnectionDriver() {
  return std::make_shared<SshConnectionDriver>(
    makeClientConnection(lookupPort("ssh")),
    server_factory_context_,
    std::make_shared<pomerium::extensions::ssh::CodecConfig>(),
    mgmt_upstream_);
}
std::string SshIntegrationTest::defaultConfig(const std::vector<std::string>& routes) {
  // TODO: we should relax this restriction
  ASSERT(!routes.empty(), "must set at least one route for the ssh listener to activate");
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
  std::string matchers;
  for (const auto& route : routes) {
    matchers += fmt::format(matcherTemplate, route, "ssh_upstream_" + route);
  }
  const auto baseConfig = fmt::format(baseConfigFmt, localhost());
  const auto httpListener = fmt::format(httpListenerFmt, localhost());
  const auto sshListener = fmt::format(sshListenerFmt,
                                       localhost(),
                                       *host_key_->formatPrivateKey(SSHKEY_PRIVATE_OPENSSH, true),
                                       *user_ca_key_->formatPrivateKey(SSHKEY_PRIVATE_OPENSSH, true),
                                       matchers);

  return absl::StrCat(baseConfig, httpListener, sshListener);
}
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec