#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "test/integration/http_integration.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"
#include <memory>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SshConnectionDriverCodecCallbacks {
public:
  virtual ~SshConnectionDriverCodecCallbacks() = default;
  virtual void onDecodingFailure(absl::string_view reason = {}) PURE;
  virtual void writeToConnection(Buffer::Instance& buffer) PURE;
};

class SshConnectionDriverCodec {
public:
  virtual ~SshConnectionDriverCodec() = default;
  virtual void setCodecCallbacks(SshConnectionDriverCodecCallbacks&) PURE;
  virtual void decode(Envoy::Buffer::Instance& buffer, bool end_stream) PURE;
};

template <>
struct codec_traits<SshConnectionDriverCodec> {
  using callbacks_type = SshConnectionDriverCodecCallbacks;
  static constexpr DirectionTags direction_read = serverKeys;
  static constexpr DirectionTags direction_write = clientKeys;
  static constexpr auto kex_mode = KexMode::Client;
  static constexpr std::string_view name = "client";
  static constexpr auto version_exchange_mode = VersionExchangeMode::Client;
};

class SecretsProviderImpl : public SecretsProvider {
public:
  std::vector<openssh::SSHKeySharedPtr> hostKeys() const override {
    return {host_key_};
  };

  openssh::SSHKeySharedPtr userCaKey() const override {
    return user_ca_key_;
  };

  openssh::SSHKeySharedPtr host_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
  openssh::SSHKeySharedPtr user_ca_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
};

class SshConnectionDriver : public Envoy::Network::ReadFilter,
                            public Network::ConnectionCallbacks,
                            public SecretsProviderImpl,
                            public std::enable_shared_from_this<SshConnectionDriver>,
                            protected TransportBase<SshConnectionDriverCodec> {
public:
  SshConnectionDriver(Network::ClientConnectionPtr client_connection,
                      Server::Configuration::ServerFactoryContext& context,
                      std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                      absl::AnyInvocable<absl::Status(wire::Message&&)> msg_handler)
      : TransportBase(context, config, *this),
        client_connection_(std::move(client_connection)),
        msg_handler_(std::move(msg_handler)) {
    server_version_ = "SSH-2.0-SshConnectionDriver";
  }

  void connect() {
    codec_callbacks_ = std::make_unique<CodecCallbacks>(*client_connection_);
    setCodecCallbacks(*codec_callbacks_);
    client_connection_->addReadFilter(shared_from_this());
    client_connection_->connect();
  }

  testing::AssertionResult
  run(Envoy::Event::Dispatcher::RunType run_type = Envoy::Event::Dispatcher::RunType::Block,
      std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    Envoy::Event::TimerPtr timeout_timer = client_connection_->dispatcher().createTimer([this]() -> void {
      client_connection_->dispatcher().exit();
    });
    timeout_timer->enableTimer(timeout);

    client_connection_->dispatcher().run(run_type);

    if (timeout_timer->enabled()) {
      timeout_timer->disableTimer();
      return testing::AssertionSuccess();
    }
    return testing::AssertionFailure();
  }

  Envoy::Event::Dispatcher& dispatcher() {
    return client_connection_->dispatcher();
  }

  void close() {
    client_connection_->close(Network::ConnectionCloseType::FlushWrite);
  }

  AssertionResult waitForKex(absl::Duration timeout) {
    auto start = absl::Now();
    while ((client_connection_->connecting() || client_connection_->state() == Network::Connection::State::Open) &&
           !on_kex_completed_.HasBeenNotified()) {
      if ((absl::Now() - start) > timeout) {
        return AssertionResult(false) << "timed out";
      }
      auto res = run(Envoy::Event::Dispatcher::RunType::NonBlock);
      if (!res) {
        return res;
      }
    }
    return AssertionResult(true);
  }

protected:
  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override {
    if (event == Network::ConnectionEvent::Connected ||
        event == Network::ConnectionEvent::ConnectedZeroRtt) {
      version_exchanger_->writeVersion(server_version_);
      return;
    }
  }
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  // Envoy::Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override {
    decode(data, end_stream);
    return Network::FilterStatus::StopIteration; // this is the only read filter
  }
  Network::FilterStatus onNewConnection() override {
    return Network::FilterStatus::Continue;
  }
  void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) override {
    read_filter_callbacks_ = &callbacks;
    read_filter_callbacks_->connection().addConnectionCallbacks(*this);
  }

  // TransportBase
  void forward(wire::Message&&, FrameTags = EffectiveCommon) override {
    PANIC("unused");
  }
  AuthInfo& authInfo() override {
    PANIC("unused");
  }
  stream_id_t streamId() const override {
    return 0xDEADBEEF;
  }

  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override {
    return client_connection_->dispatcher();
  }

  ChannelIDManager& channelIdManager() override {
    return channel_id_manager_;
  }

  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override {
    TransportBase::onKexCompleted(kex_result, initial_kex);
    kex_result_ = kex_result;
    on_kex_completed_.Notify();
  }

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override {
    for (auto msg_type : {
           wire::SshMessageType::ServiceAccept,
           wire::SshMessageType::GlobalRequest,
           wire::SshMessageType::RequestSuccess,
           wire::SshMessageType::RequestFailure,
           wire::SshMessageType::Ignore,
           wire::SshMessageType::Debug,
           wire::SshMessageType::Unimplemented,
           wire::SshMessageType::Disconnect,
           wire::SshMessageType::UserAuthRequest,
           wire::SshMessageType::UserAuthInfoResponse,
           wire::SshMessageType::ChannelOpen,
           wire::SshMessageType::ChannelOpenConfirmation,
           wire::SshMessageType::ChannelOpenFailure,
           wire::SshMessageType::ChannelWindowAdjust,
           wire::SshMessageType::ChannelData,
           wire::SshMessageType::ChannelExtendedData,
           wire::SshMessageType::ChannelEOF,
           wire::SshMessageType::ChannelClose,
           wire::SshMessageType::ChannelRequest,
           wire::SshMessageType::ChannelSuccess,
           wire::SshMessageType::ChannelFailure,
         }) {
      dispatcher.registerHandler(msg_type, this);
    }
  }

  absl::Status handleMessage(wire::Message&& msg) override {
    return msg_handler_(std::move(msg));
  }

  class CodecCallbacks : public SshConnectionDriverCodecCallbacks {
  public:
    explicit CodecCallbacks(Network::ClientConnection& client_connection)
        : client_connection_(client_connection) {}
    void onDecodingFailure(absl::string_view reason = {}) override {
      FAIL() << reason;
      client_connection_.close(Network::ConnectionCloseType::AbortReset, reason);
    }

    void writeToConnection(Buffer::Instance& buffer) override {
      client_connection_.write(buffer, false);
    }

    Network::ClientConnection& client_connection_;
  };

  Envoy::Network::ReadFilterCallbacks* read_filter_callbacks_{nullptr};
  Network::ClientConnectionPtr client_connection_;

  absl::Notification on_kex_completed_;
  std::shared_ptr<KexResult> kex_result_;
  ChannelIDManager channel_id_manager_;

  absl::AnyInvocable<absl::Status(wire::Message&&)> msg_handler_;
  std::unique_ptr<CodecCallbacks> codec_callbacks_;
};

namespace test {

class SshIntegrationTest : public SecretsProviderImpl,
                           public HttpIntegrationTest {
  // Implementation note:
  // SecretsProviderImpl has to be a separate base class, initialized before HttpIntegrationTest,
  // and must create the ssh keys. The HttpIntegrationTest constructor needs the string config,
  // which we need to format using the generated keys. If we stored the keys in SshIntegrationTest
  // and initialized them e.g. inside defaultConfig(), they would be deleted when the members of
  // SshIntegrationTest are default-initialized, which happens after the SshIntegrationTest
  // constructor completes.
protected:
  template <typename... Args>
  SshIntegrationTest(const std::vector<std::pair<std::string, std::string>>& routes, Args&&... base_args)
      : HttpIntegrationTest(std::forward<Args>(base_args)..., defaultConfig(routes)) {
    // setUpstreamCount(1); // upstream 0 = default http server, upstream 1 = management grpc server
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      ASSERT(bootstrap.mutable_static_resources()->clusters_size() == 1);
      auto* mgmt_cluster = bootstrap.mutable_static_resources()->add_clusters();
      mgmt_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      mgmt_cluster->set_name("fake_mgmt");
      mgmt_cluster->mutable_load_assignment()->set_cluster_name("fake_mgmt");
      ConfigHelper::setHttp2(*mgmt_cluster);
    });
  }

  void initialize() override {

    HttpIntegrationTest::initialize();

    registerTestServerPorts({"http", "ssh"}, test_server_);
  }

  void createUpstreams() override {
    HttpIntegrationTest::createUpstreams();
    addFakeUpstream(Http::CodecType::HTTP2);
    mgmt_upstream_ = fake_upstreams_.back().get();
  }

  std::string defaultConfig(const std::vector<std::pair<std::string, std::string>>& routes) {
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
                                  exact: {}
                        on_match:
                          action:
                            name: route
                            typed_config:
                              '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.action.v3.RouteAction
                              cluster: {}
                              timeout: 0s
    )";
    std::string matchers;
    for (const auto& [host, cluster] : routes) {
      matchers += fmt::format(matcherTemplate, host, cluster);
    }
    constexpr auto cfgTemplate = R"(
  - name: ssh
    address:
      socket_address:
        address: 127.0.0.1
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
          route_config:
            name: route_config
            virtual_hosts:
              - name: ssh
                hosts:
                  - '*'
                routes:
                  matcher_list:
                    matchers: {}
          filters:
            - name: envoy.filters.generic.router
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.filters.network.generic_proxy.router.v3.Router
                bind_upstream_connection: true
    )";
    return absl::StrCat(ConfigHelper::baseConfig(), ConfigHelper::httpProxyConfig(),
                        fmt::format(cfgTemplate,
                                    *host_key_->formatPrivateKey(SSHKEY_PRIVATE_OPENSSH, true),
                                    *user_ca_key_->formatPrivateKey(SSHKEY_PRIVATE_OPENSSH, true),
                                    matchers));
  }

  std::shared_ptr<SshConnectionDriver> makeSshConnectionDriver(absl::AnyInvocable<absl::Status(wire::Message&&)> msg_handler) {
    return std::make_shared<SshConnectionDriver>(
      makeClientConnection(lookupPort("ssh")),
      server_factory_context_,
      std::make_shared<pomerium::extensions::ssh::CodecConfig>(),
      std::move(msg_handler));
  }

  FakeUpstream* mgmt_upstream_;
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec