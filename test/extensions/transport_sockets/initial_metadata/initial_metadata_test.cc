#include "test/integration/base_integration_test.h"
#include "gtest/gtest.h"

using namespace std::literals;

namespace Envoy {
namespace test {

class InitialMetadataIntegrationTest : public testing::Test, public BaseIntegrationTest {
public:
  InitialMetadataIntegrationTest()
      : BaseIntegrationTest(Network::Address::IpVersion::v4, config()) {
  }

  void setTestPayload(const std::string& payload) {
    test_payload_ = payload;
  }

  void initialize() override {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* filterChain = bootstrap.mutable_static_resources()->mutable_listeners(0)->mutable_filter_chains(0)->mutable_filters();
      TestUtility::loadFromYaml(fmt::format(R"(
        name: set-filter-state
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.set_filter_state.v3.Config
          on_new_connection:
          - object_key: pomerium.initial_metadata_payload
            format_string:
              text_format_source:
                inline_string: "{}"
            shared_with_upstream: TRANSITIVE
      )",
                                            test_payload_),
                                *filterChain->Add());
      filterChain->SwapElements(0, 1);
    });
    BaseIntegrationTest::initialize();
  }

protected:
  std::string config() {
    return absl::StrCat(
      ConfigHelper::baseConfigNoListeners(),
      // following cluster 0
      R"(
    transport_socket:
      name: pomerium.transport_sockets.initial_metadata
      typed_config:
        "@type": type.googleapis.com/pomerium.extensions.transport_sockets.initial_metadata.Config
        transport_socket:
          name: envoy.transport_sockets.raw_buffer
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer
        magic: AQIDBA==

  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    filter_chains:
    - filters:
      - name: tcp
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcpproxy_stats
          cluster: cluster_0
    )");
  }

  std::string test_payload_ = "testing";
};

TEST_F(InitialMetadataIntegrationTest, Test) {
  setTestPayload("testing");
  initialize();

  auto client = makeTcpConnection(lookupPort("listener_0"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  ASSERT_TRUE(client->connected());

  ASSERT_TRUE(client->write("hello world"));
  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5 + test_payload_.size() + "hello world"sv.size(), &data));

  ASSERT_EQ(data, "\x01\x02\x03\x04"
                  "\x07"
                  "testing"
                  "hello world"s);
  client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

} // namespace test
} // namespace Envoy