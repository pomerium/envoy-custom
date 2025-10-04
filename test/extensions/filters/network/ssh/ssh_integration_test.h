#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
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

class TaskCallbacks {
public:
  virtual ~TaskCallbacks() = default;
  virtual void sendMessage(wire::Message&&) PURE;
  virtual void taskSuccess() PURE;
  virtual void taskFailure(absl::Status) PURE;
  virtual KexResult& kexResult() PURE;
  virtual openssh::SSHKey& clientKey() PURE;
  virtual void waitForManagementRequest(Protobuf::Message& req) PURE;
  virtual void sendManagementResponse(const Protobuf::Message& resp) PURE;
};

#define FAIL_IF_NOT_OK(status)                                 \
  if (auto s = ::test::detail::to_status((status)); !s.ok()) { \
    callbacks_->taskFailure(s);                                \
    return;                                                    \
  }

#define OR_FAIL                                                                                        \
  [&](const auto& msg) {                                                                               \
    callbacks_->taskFailure(absl::InternalError(fmt::format("received unexpected message: {}", msg))); \
  }

class Task : public SshMessageMiddleware {
  friend class SshConnectionDriver;

public:
  Task() = default;
  virtual ~Task() = default;
  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;

protected:
  virtual void start() PURE;
  virtual void onMessageReceived(const wire::Message& msg) PURE;

  TaskCallbacks* callbacks_;
  stream_id_t stream_id_;

private:
  void setTaskCallbacks(TaskCallbacks& cb, stream_id_t stream_id) {
    callbacks_ = &cb;
    stream_id_ = stream_id;
  }
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) final {
    onMessageReceived(msg);
    return MiddlewareResult::Break;
  }
};

using TaskPtr = std::unique_ptr<Task>;

class SshConnectionDriver : public Envoy::Network::ReadFilter,
                            public Network::ConnectionCallbacks,
                            public SecretsProviderImpl,
                            public TaskCallbacks,
                            public std::enable_shared_from_this<SshConnectionDriver>,
                            protected TransportBase<SshConnectionDriverCodec> {
public:
  SshConnectionDriver(Network::ClientConnectionPtr client_connection,
                      Server::Configuration::ServerFactoryContext& context,
                      std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                      FakeUpstream* mgmt_upstream)
      : TransportBase(context, config, *this),
        client_connection_(std::move(client_connection)),
        mgmt_upstream_(mgmt_upstream) {
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
    Envoy::Event::TimerPtr timeout_timer = connectionDispatcher()->createTimer([this]() -> void {
      connectionDispatcher()->exit();
    });
    timeout_timer->enableTimer(timeout);

    connectionDispatcher()->run(run_type);

    if (timeout_timer->enabled()) {
      timeout_timer->disableTimer();
      return testing::AssertionSuccess();
    }
    return testing::AssertionFailure();
  }

  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override {
    return client_connection_->dispatcher();
  }

  void close() {
    client_connection_->close(Network::ConnectionCloseType::FlushWrite);
  }

  // TaskCallbacks
  void sendMessage(wire::Message&& msg) override {
    if (auto r = sendMessageToConnection(std::move(msg)); !r.ok()) {
      terminate(r.status());
    }
  }
  void waitForManagementRequest(Protobuf::Message& req) override {
    auto res = mgmt_stream_->waitForGrpcMessage(*connectionDispatcher(), req);
    if (!res) {
      terminate(absl::InternalError("waitForManagementRequest failed"));
    }
  }
  void sendManagementResponse(const Protobuf::Message& resp) override {
    mgmt_stream_->sendGrpcMessage(resp);
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

    auto res = mgmt_upstream_->waitForHttpConnection(*connectionDispatcher(), mgmt_connection_);
    if (!res) {
      return res;
    }
    res = mgmt_connection_->waitForNewStream(*connectionDispatcher(), mgmt_stream_);
    if (!res) {
      return res;
    }
    mgmt_stream_->startGrpcStream();
    pomerium::extensions::ssh::ClientMessage connected;
    res = mgmt_stream_->waitForGrpcMessage(*connectionDispatcher(), connected);
    if (!res) {
      return res;
    }
    auto event = connected.event().downstream_connected();
    stream_id_ = event.stream_id();
    return AssertionResult(true);
  }

  AssertionResult runTask(Task&& t) {
    t.setTaskCallbacks(*this, streamId());
    installMiddleware(&t);
    connectionDispatcher()->post([&] { t.start(); });
    auto timeoutStatus = run(Envoy::Event::Dispatcher::RunType::RunUntilExit);
    uninstallMiddleware(&t);

    if (!timeoutStatus) {
      ASSERT(!task_result_.has_value());
      return timeoutStatus;
    }
    ASSERT(task_result_.has_value());
    return std::exchange(task_result_, {}).value();
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
    ASSERT(stream_id_ != 0);
    return stream_id_;
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
    dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
  }

  absl::Status handleMessage(wire::Message&& msg) override {
    auto dc = msg.message.get<wire::DisconnectMsg>();
    auto desc = *dc.description;
    return absl::CancelledError(fmt::format("received disconnect: {}{}{}",
                                            openssh::disconnectCodeToString(*dc.reason_code),
                                            desc.empty() ? "" : ": ", desc));
  }

  // TaskCallbacks
  void taskSuccess() override {
    task_result_ = AssertionResult(true);
    connectionDispatcher()->exit();
  }
  void taskFailure(absl::Status stat) override {
    ADD_FAILURE() << statusToString(stat);
    task_result_ = AssertionResult(false);
    connectionDispatcher()->exit();
  }
  KexResult& kexResult() override {
    return *kex_result_;
  }
  openssh::SSHKey& clientKey() override {
    return *host_key_;
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

  std::unique_ptr<CodecCallbacks> codec_callbacks_;

  std::optional<AssertionResult> task_result_;

  FakeUpstream* mgmt_upstream_;
  FakeHttpConnectionPtr mgmt_connection_;
  FakeStreamPtr mgmt_stream_;

  stream_id_t stream_id_;
};

namespace test {

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

  std::shared_ptr<SshConnectionDriver> makeSshConnectionDriver() {
    return std::make_shared<SshConnectionDriver>(
      makeClientConnection(lookupPort("ssh")),
      server_factory_context_,
      std::make_shared<pomerium::extensions::ssh::CodecConfig>(),
      mgmt_upstream_);
  }

  FakeUpstream* mgmt_upstream_;
};

namespace Tasks {

class RequestUserAuthService : public Task {
public:
  void start() override {
    callbacks_->sendMessage(wire::ServiceRequestMsg{
      .service_name = "ssh-userauth"s,
    });
  }

  void onMessageReceived(const wire::Message& msg) override {
    msg.visit(
      [&](const wire::ServiceAcceptMsg&) {
        callbacks_->taskSuccess();
      },
      OR_FAIL);
  }
};

class Authenticate : public Task {
public:
  void start() override {
    wire::UserAuthRequestMsg req;
    req.username = username;
    req.service_name = "ssh-connection";

    auto& key = callbacks_->clientKey();
    wire::PubKeyUserAuthRequestMsg pubkeyReq{
      .has_signature = true,
      .public_key_alg = key.signatureAlgorithmsForKeyType()[0],
      .public_key = key.toPublicKeyBlob(),
    };
    // compute signature
    Envoy::Buffer::OwnedImpl buf;
    wire::write_opt<wire::LengthPrefixed>(buf, callbacks_->kexResult().session_id);
    constexpr static wire::field<std::string, wire::LengthPrefixed> method_name =
      std::string(wire::PubKeyUserAuthRequestMsg::submsg_key);
    FAIL_IF_NOT_OK(wire::encodeMsg(buf, req.type,
                                   req.username,
                                   req.service_name,
                                   method_name,
                                   pubkeyReq.has_signature,
                                   pubkeyReq.public_key_alg,
                                   pubkeyReq.public_key));
    auto sig = key.sign(wire::flushTo<bytes>(buf), pubkeyReq.public_key_alg);
    FAIL_IF_NOT_OK(sig);
    pubkeyReq.signature = *sig;
    req.request = std::move(pubkeyReq);
    callbacks_->sendMessage(std::move(req));

    ClientMessage clientMsg;
    callbacks_->waitForManagementRequest(clientMsg);
    if (clientMsg.auth_request().auth_method() == "publickey") {
      pomerium::extensions::ssh::FilterMetadata filterMetadata;
      filterMetadata.set_stream_id(stream_id_);
      // Only the stream id is set here, not channel id.
      // TODO: maybe refactor this api to be less confusing

      ServerMessage serverMsg;
      (*serverMsg.mutable_auth_response()
          ->mutable_allow()
          ->mutable_internal()
          ->mutable_set_metadata()
          ->mutable_typed_filter_metadata())["com.pomerium.ssh"]
        .PackFrom(filterMetadata);
      callbacks_->sendManagementResponse(serverMsg);
    }
  };

  void onMessageReceived(const wire::Message& msg) override {
    msg.visit(
      [&](const wire::UserAuthSuccessMsg&) {
        callbacks_->taskSuccess();
      },
      [&](const wire::UserAuthFailureMsg& msg) {
        callbacks_->taskFailure(absl::InternalError(fmt::format("received auth failure: {}", msg)));
      },
      [&](const wire::UserAuthBannerMsg&) {
        // ignore for now
      },
      OR_FAIL);
  };

  std::string username;
};

} // namespace Tasks

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec