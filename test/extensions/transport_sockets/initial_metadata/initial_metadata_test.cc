#include "source/common/types.h"
#include "test/integration/base_integration_test.h"
#include "gtest/gtest.h"
#include "api/extensions/transport_sockets/initial_metadata/initial_metadata.pb.h"
#include "api/extensions/transport_sockets/initial_metadata/initial_metadata.pb.validate.h"

using namespace std::literals;

namespace Envoy {
namespace test {

class InitialMetadataIntegrationTest : public testing::Test, public BaseIntegrationTest {
public:
  InitialMetadataIntegrationTest()
      : BaseIntegrationTest(Network::Address::IpVersion::v4, config()) {
  }

  void initialize() override {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* cluster0TransportSocket = bootstrap.mutable_static_resources()
                                        ->mutable_clusters(0)
                                        ->mutable_transport_socket();
      pomerium::extensions::transport_sockets::initial_metadata::Config config;
      ASSERT_TRUE(cluster0TransportSocket->mutable_typed_config()->UnpackTo(&config));
      config.set_magic(to_string_view(magic_));
      if (default_payload_.has_value()) {
        config.mutable_default_payload()->set_value(default_payload_.value());
      }
      ASSERT_TRUE(cluster0TransportSocket->mutable_typed_config()->PackFrom(config));
    });

    if (should_set_filter_state_) {
      config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
        auto* filterChain = bootstrap.mutable_static_resources()
                              ->mutable_listeners(0)
                              ->mutable_filter_chains(0)
                              ->mutable_filters();
        constexpr auto set_filter_state_config = R"(
        name: set-filter-state
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.set_filter_state.v3.Config
          on_new_connection:
          - object_key: pomerium.initial_metadata_payload
            format_string:
              text_format_source:
                inline_string: "{}"
            shared_with_upstream: TRANSITIVE
      )";
        TestUtility::loadFromYaml(fmt::format(set_filter_state_config,
                                              test_payload_),
                                  *filterChain->Add());
        filterChain->SwapElements(0, 1);
      });
    }
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

  fixed_bytes<4> magic_ = {1, 2, 3, 4};
  std::optional<std::string> default_payload_;
  std::string test_payload_ = "testing";
  bool should_set_filter_state_ = true;
};

TEST_F(InitialMetadataIntegrationTest, Test) {
  initialize();

  auto client = makeTcpConnection(lookupPort("listener_0"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  ASSERT_TRUE(client->connected());

  ASSERT_TRUE(client->write("hello world"));
  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(
    5 + test_payload_.size() + "hello world"sv.size(), &data));

  ASSERT_EQ(data, "\x01\x02\x03\x04"
                  "\x07"
                  "testing"
                  "hello world"s);
  client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_F(InitialMetadataIntegrationTest, TestDefaultPayload) {
  default_payload_ = "default-payload";
  should_set_filter_state_ = false;
  initialize();

  auto client = makeTcpConnection(lookupPort("listener_0"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  ASSERT_TRUE(client->connected());

  ASSERT_TRUE(client->write("hello world"));
  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(
    5 + default_payload_->size() + "hello world"sv.size(), &data));

  ASSERT_EQ(data, "\x01\x02\x03\x04"
                  "\x0F"
                  "default-payload"
                  "hello world"s);
  client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_F(InitialMetadataIntegrationTest, TestNoFilterStateOrDefaultPayload) {
  should_set_filter_state_ = false;
  initialize();

  auto client = makeTcpConnection(lookupPort("listener_0"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  ASSERT_TRUE(client->connected());

  ASSERT_TRUE(client->write("hello world"));
  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData("hello world"sv.size(), &data));

  ASSERT_EQ(data, "hello world"s);
  client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_F(InitialMetadataIntegrationTest, TestPayloadTooLarge) {
  test_payload_ = std::string(256, 'a');
  initialize();

  auto client = makeTcpConnection(lookupPort("listener_0"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  ASSERT_TRUE(client->connected());

  ASSERT_TRUE(client->write("hello world"));
  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData("hello world"sv.size(), &data));

  ASSERT_EQ(data, "hello world"s);
  client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST(ConfigValidationTest, InvalidMagic) {
  pomerium::extensions::transport_sockets::initial_metadata::Config config;
  constexpr auto base_config = R"(
        transport_socket:
          name: envoy.transport_sockets.raw_buffer
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer
)";

  // magic: aaaaa
  auto invalidConfigMagicTooLong = absl::StrCat(base_config, R"(
        magic: YWFhYWE=
  )");

  // magic: aaa
  auto invalidConfigMagicTooShort = absl::StrCat(base_config, R"(
        magic: YWFh
  )");

  EXPECT_THROW_WITH_REGEX(TestUtility::loadFromYamlAndValidate(invalidConfigMagicTooLong,
                                                               config),
                          Envoy::ProtoValidationException,
                          "ConfigValidationError.Magic: value length must be 4 bytes");

  EXPECT_THROW_WITH_REGEX(TestUtility::loadFromYamlAndValidate(invalidConfigMagicTooShort,
                                                               config),
                          Envoy::ProtoValidationException,
                          "ConfigValidationError.Magic: value length must be 4 bytes");

  std::vector<uint8_t> invalidChars{'\x04', '\x05', '\x50', '\x48', '\x14', '\x15', '\x16', '\x17'};
  for (auto ch : invalidChars) {
    constexpr auto config_fmt = R"(
        magic: {}
    )";
    auto invalidMagicBase64 = absl::Base64Escape(to_string(fixed_bytes<4>{ch, 'a', 'a', 'a'}));
    auto invalidConfig = absl::StrCat(base_config, fmt::format(config_fmt, invalidMagicBase64));

    EXPECT_THROW_WITH_REGEX(TestUtility::loadFromYamlAndValidate(invalidConfig,
                                                                 config),
                            Envoy::ProtoValidationException,
                            "ConfigValidationError.Magic: value does not match regex pattern");
  }
}

TEST(ConfigValidationTest, DefaultPayloadTooLarge) {
  pomerium::extensions::transport_sockets::initial_metadata::Config config;
  constexpr auto config_fmt = R"(
        transport_socket:
          name: envoy.transport_sockets.raw_buffer
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer
        magic: YWFhYQ==
        default_payload: {}
)";

  auto invalidConfigDefaultPayloadTooLarge =
    fmt::format(config_fmt, absl::Base64Escape(std::string(256, 'a')));

  EXPECT_THROW_WITH_REGEX(
    TestUtility::loadFromYamlAndValidate(invalidConfigDefaultPayloadTooLarge,
                                         config),
    Envoy::ProtoValidationException,
    "ConfigValidationError.DefaultPayload: value length must be at most 255 bytes");
}

} // namespace test
} // namespace Envoy