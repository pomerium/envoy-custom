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
#include <chrono>
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
  virtual void taskFailure(absl::Status err) PURE;
  virtual KexResult& kexResult() PURE;
  virtual openssh::SSHKey& clientKey() PURE;
  virtual void waitForManagementRequest(Protobuf::Message& req) PURE;
  virtual void sendManagementResponse(const Protobuf::Message& resp) PURE;
  virtual void setTimeout(std::chrono::milliseconds timeout) PURE;
};

#define OR_FAIL                                                           \
  [&](const auto& msg) {                                                  \
    ADD_FAILURE() << fmt::format("received unexpected message: {}", msg); \
  }

inline std::chrono::milliseconds defaultTimeout() {
  CONSTRUCT_ON_FIRST_USE(std::chrono::milliseconds,
                         isDebuggerAttached()
                           ? std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours(1))
                           : std::chrono::milliseconds(10000));
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
  virtual void onMessageReceived(wire::Message& msg) PURE;

  // Can be overridden to provide more details/current state on failure
  virtual absl::Status errorDetails() {
    return absl::InternalError("task failed via assertion");
  }

  TaskCallbacks* callbacks_;
  stream_id_t stream_id_;

private:
  void setTaskCallbacks(TaskCallbacks& cb, stream_id_t stream_id) {
    callbacks_ = &cb;
    stream_id_ = stream_id;
  }
  void startInternal() {
    start();
    if (testing::Test::HasFailure()) {
      callbacks_->taskFailure(errorDetails());
    }
  }
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) final {
    // FIXME: this needs a way to filter channel messages intended for other middlewares
    onMessageReceived(msg);
    if (testing::Test::HasFailure()) {
      callbacks_->taskFailure(errorDetails());
    }
    return MiddlewareResult::Break;
  }
};

using TaskPtr = std::unique_ptr<Task>;

class SshConnectionDriver : public Envoy::Network::ReadFilter,
                            public Network::ConnectionCallbacks,
                            public SecretsProviderImpl,
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

  void sendMessage(wire::Message&& msg) {
    if (auto r = sendMessageToConnection(std::move(msg)); !r.ok()) {
      terminate(r.status());
    }
  }

  AssertionResult waitForKex(std::chrono::milliseconds timeout = defaultTimeout()) {
    auto start = std::chrono::system_clock::now();
    while ((client_connection_->connecting() || client_connection_->state() == Network::Connection::State::Open) &&
           !on_kex_completed_.HasBeenNotified()) {
      if ((std::chrono::system_clock::now() - start) > timeout) {
        return AssertionResult(false) << "timed out";
      }
      auto res = run(Envoy::Event::Dispatcher::RunType::NonBlock);
      if (!res) {
        return res;
      }
    }

    auto res = mgmt_upstream_->waitForHttpConnection(*connectionDispatcher(), mgmt_connection_, timeout);
    if (!res) {
      return res;
    }
    res = mgmt_connection_->waitForNewStream(*connectionDispatcher(), mgmt_stream_, timeout);
    if (!res) {
      return res;
    }
    mgmt_stream_->startGrpcStream();
    pomerium::extensions::ssh::ClientMessage connected;
    res = mgmt_stream_->waitForGrpcMessage(*connectionDispatcher(), connected, timeout);
    if (!res) {
      return res;
    }
    auto event = connected.event().downstream_connected();
    stream_id_ = event.stream_id();
    return AssertionResult(true);
  }

  template <typename TaskType, typename... Args>
  AssertionResult startTaskAndWait(Args&&... task_args) {
    auto t = std::make_unique<TaskType>(std::forward<Args>(task_args)...);
    auto cb = std::make_unique<TaskCallbacksImpl>(*this, std::move(t));
    LinkedList::moveIntoList(std::move(cb), active_tasks_);
    auto timeoutStatus = run(Envoy::Event::Dispatcher::RunType::RunUntilExit);
    if (!timeoutStatus) {
      return timeoutStatus;
    }
    return AssertionResult(!testing::Test::HasFailure());
  }

  template <typename TaskType, typename... Args>
  void startTask(Args&&... task_args) {
    auto t = std::make_unique<TaskType>(std::forward<Args>(task_args)...);
    auto cb = std::make_unique<TaskCallbacksImpl>(*this, std::move(t));
    LinkedList::moveIntoList(std::move(cb), active_tasks_);
  }

  AssertionResult waitAllTasksComplete() {
    // Logic here copied from waitForWithDispatcherRun
    absl::MutexLock lock(&lock_);
    auto& time_system =
      dynamic_cast<Envoy::Event::TestTimeSystem&>(connectionDispatcher()->timeSource());
    Envoy::Event::TestTimeSystem::RealTimeBound bound(defaultTimeout());
    auto condition = [this] { return active_tasks_.empty(); };
    while (bound.withinBound()) {
      // Wake up periodically to run the client dispatcher.
      if (time_system.waitFor(lock_, absl::Condition(&condition), 5ms * TIMEOUT_FACTOR)) {
        return AssertionResult(testing::Test::HasFailure());
      }
      connectionDispatcher()->run(Envoy::Event::Dispatcher::RunType::NonBlock);
    }
    return AssertionResult(false) << "timed out waiting for tasks to be completed";
  }

  stream_id_t streamId() const override {
    ASSERT(stream_id_ != 0);
    return stream_id_;
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

  ChannelIDManager& channelIdManager() override {
    PANIC("unused");
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
  class TaskCallbacksImpl : public TaskCallbacks,
                            public LinkedObject<TaskCallbacksImpl> {
  public:
    TaskCallbacksImpl(SshConnectionDriver& d, std::unique_ptr<Task> t)
        : parent_(d),
          task_(std::move(t)) {
      task_->setTaskCallbacks(*this, parent_.streamId());
      parent_.installMiddleware(task_.get());
      parent_.connectionDispatcher()->post([this] { task_->startInternal(); });
    }
    void taskSuccess() override {
      ASSERT(!testing::Test::HasFailure());
      if (timeout_timer_ != nullptr) {
        timeout_timer_->disableTimer();
      }
      parent_.uninstallMiddleware(task_.get());
      ASSERT(inserted());
      auto self = removeFromList(parent_.active_tasks_);
      parent_.connectionDispatcher()->exit();
    }
    void taskFailure(absl::Status stat) override {
      if (timeout_timer_ != nullptr) {
        timeout_timer_->disableTimer();
      }
      parent_.uninstallMiddleware(task_.get());
      ASSERT(inserted());
      auto self = removeFromList(parent_.active_tasks_);
      ADD_FAILURE() << statusToString(stat);
      parent_.connectionDispatcher()->exit();
    }
    KexResult& kexResult() override {
      return *parent_.kex_result_;
    }
    openssh::SSHKey& clientKey() override {
      return *parent_.host_key_;
    }
    void setTimeout(std::chrono::milliseconds timeout) override {
      if (timeout_timer_ != nullptr) {
        timeout_timer_->disableTimer();
      }
      timeout_timer_ = parent_.connectionDispatcher()->createTimer([this] {
        taskFailure(absl::DeadlineExceededError("task timed out"));
      });
      timeout_timer_->enableTimer(timeout);
    }

    void sendMessage(wire::Message&& msg) override {
      parent_.sendMessage(std::move(msg));
    }
    void waitForManagementRequest(Protobuf::Message& req) override {
      auto res = parent_.mgmt_stream_->waitForGrpcMessage(
        *parent_.connectionDispatcher(), req, defaultTimeout());
      if (!res) {
        parent_.terminate(absl::InternalError("waitForManagementRequest failed"));
      }
    }
    void sendManagementResponse(const Protobuf::Message& resp) override {
      parent_.mgmt_stream_->sendGrpcMessage(resp);
    }

    SshConnectionDriver& parent_;
    std::unique_ptr<Task> task_;
    Envoy::Event::TimerPtr timeout_timer_;
  };

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

  std::unique_ptr<CodecCallbacks> codec_callbacks_;

  FakeUpstream* mgmt_upstream_;
  FakeHttpConnectionPtr mgmt_connection_;
  FakeStreamPtr mgmt_stream_;

  stream_id_t stream_id_;

  std::list<std::unique_ptr<TaskCallbacksImpl>> active_tasks_;

private:
  absl::Mutex lock_;
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
  SshIntegrationTest(std::vector<std::string> ssh_routes, Args&&... base_args)
      : HttpIntegrationTest(std::forward<Args>(base_args)..., defaultConfig(ssh_routes)) {
    fake_upstreams_count_ = 0; // add our upstreams manually
    config_helper_.addConfigModifier([ssh_routes](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      ASSERT(bootstrap.mutable_static_resources()->clusters_size() == 0);
      auto fakeMgmtCluster = ConfigHelper::buildStaticCluster("fake_mgmt", 0, "127.0.0.1");
      ConfigHelper::setHttp2(fakeMgmtCluster);
      bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(fakeMgmtCluster);

      ConfigHelper::HttpProtocolOptions http1_protocol_options;
      http1_protocol_options.mutable_explicit_http_config()->clear_http2_protocol_options();
      http1_protocol_options.mutable_explicit_http_config()->mutable_http_protocol_options();

      auto httpCluster1 = ConfigHelper::buildStaticCluster("http_cluster_1", 0, "127.0.0.1");
      ConfigHelper::setProtocolOptions(httpCluster1, http1_protocol_options);
      bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(httpCluster1);

      auto httpCluster2 = ConfigHelper::buildStaticCluster("http_cluster_2", 0, "127.0.0.1");
      ConfigHelper::setHttp2(httpCluster2);
      bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(httpCluster2);

      for (const auto& route : ssh_routes) {
        auto c = ConfigHelper::buildStaticCluster("ssh_upstream_" + route, 0, "127.0.0.1");
        bootstrap.mutable_static_resources()->add_clusters()->CopyFrom(c);
      }
    });
    mgmt_upstream_ = &addFakeUpstream(Http::CodecType::HTTP2);
    http_upstream_1_ = &addFakeUpstream(Http::CodecType::HTTP1);
    http_upstream_2_ = &addFakeUpstream(Http::CodecType::HTTP1);
    for (size_t i = 0; i < ssh_routes.size(); i++) {
      ssh_upstreams_.push_back(&addFakeUpstream(Http::CodecType::HTTP1)); // codec type is unused here
    }
  }

  void initialize() override {
    HttpIntegrationTest::initialize();
    registerTestServerPorts({"http", "ssh"});
  }

  std::string defaultConfig(const std::vector<std::string>& routes) {
    // TODO: we should relax this restriction
    ASSERT(!routes.empty(), "must set at least one route for the ssh listener to activate");
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
    for (const auto& route : routes) {
      matchers += fmt::format(matcherTemplate, route, "ssh_upstream_" + route);
    }
    constexpr auto baseConfig = R"(
admin:
  access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: "/dev/null"
  address:
    socket_address:
      address: 127.0.0.1
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
    constexpr auto httpListener = R"(
  - name: http
    address:
      socket_address:
        address: 127.0.0.1
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
              not_health_check_filter:  {}
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
    constexpr auto sshListener = R"(
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

    return absl::StrCat(baseConfig,
                        httpListener,
                        fmt::format(sshListener,
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
  FakeUpstream* http_upstream_1_;
  FakeUpstream* http_upstream_2_;
  std::vector<FakeUpstream*> ssh_upstreams_;
};

namespace Tasks {

class RequestUserAuthService : public Task {
public:
  void start() override {
    callbacks_->sendMessage(wire::ServiceRequestMsg{
      .service_name = "ssh-userauth"s,
    });
  }

  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ServiceAcceptMsg&) {
        callbacks_->taskSuccess();
      },
      OR_FAIL);
  }
};

class Authenticate : public Task {
public:
  Authenticate(std::string username = "user", bool internal = true)
      : username_(username),
        internal_(internal) {}
  void start() override {
    wire::UserAuthRequestMsg req;
    req.username = username_;
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
    ASSERT_OK(wire::encodeMsg(buf, req.type,
                              req.username,
                              req.service_name,
                              method_name,
                              pubkeyReq.has_signature,
                              pubkeyReq.public_key_alg,
                              pubkeyReq.public_key));
    auto sig = key.sign(wire::flushTo<bytes>(buf), pubkeyReq.public_key_alg);
    ASSERT_OK(sig);
    pubkeyReq.signature = *sig;
    req.request = std::move(pubkeyReq);
    callbacks_->sendMessage(std::move(req));

    ClientMessage clientMsg;
    callbacks_->waitForManagementRequest(clientMsg);
    ASSERT_EQ("publickey", clientMsg.auth_request().auth_method());
    pomerium::extensions::ssh::FilterMetadata filterMetadata;
    filterMetadata.set_stream_id(stream_id_);
    // Only the stream id is set here, not channel id.
    // TODO: maybe refactor this api to be less confusing

    if (internal_) {
      ServerMessage serverMsg;
      (*serverMsg.mutable_auth_response()
          ->mutable_allow()
          ->mutable_internal()
          ->mutable_set_metadata()
          ->mutable_typed_filter_metadata())["com.pomerium.ssh"]
        .PackFrom(filterMetadata);
      callbacks_->sendManagementResponse(serverMsg);
    } else {
      PANIC("unimplemented");
    }
  };

  void onMessageReceived(wire::Message& msg) override {
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

  const std::string username_;
  const bool internal_{};
};

class RequestReversePortForward : public Task {
public:
  RequestReversePortForward(const std::string& address, uint32_t port, uint32_t server_port)
      : address_(address),
        port_(port),
        server_port_(server_port) {}
  void start() override {
    callbacks_->sendMessage(wire::GlobalRequestMsg{
      .want_reply = true,
      .request = wire::TcpipForwardMsg{
        .remote_address = address_,
        .remote_port = port_,
      },
    });
    ClientMessage clientMsg;
    callbacks_->waitForManagementRequest(clientMsg);
    ASSERT_EQ(address_, clientMsg.global_request().tcpip_forward_request().remote_address());
    ASSERT_EQ(port_, clientMsg.global_request().tcpip_forward_request().remote_port());
    ServerMessage serverMsg;
    serverMsg.mutable_global_request_response()
      ->set_success(true);
    serverMsg.mutable_global_request_response()
      ->mutable_tcpip_forward_response()
      ->set_server_port(server_port_);
    callbacks_->sendManagementResponse(serverMsg);
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](wire::GlobalRequestSuccessMsg& msg) {
        ASSERT_OK(msg.resolve<wire::TcpipForwardResponseMsg>());
        ASSERT_EQ(server_port_, *msg.response.get<wire::TcpipForwardResponseMsg>().server_port);
        callbacks_->taskSuccess();
      },
      [&](const wire::GlobalRequestFailureMsg& msg) {
        callbacks_->taskFailure(absl::InternalError(fmt::format("request failed: {}", msg)));
      },
      OR_FAIL);
  };

  const std::string address_;
  const uint32_t port_;
  const uint32_t server_port_;
};

class AcceptReversePortForward : public Task {
public:
  AcceptReversePortForward(const std::string& address_connected, uint32_t port_connected,
                           uint32_t local_channel_id, uint32_t* remote_channel_id)
      : address_connected_(address_connected),
        port_connected_(port_connected),
        local_channel_id_(local_channel_id),
        remote_channel_id_(remote_channel_id) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelOpenMsg& open_msg) {
        ASSERT_EQ(wire::ChannelWindowSize, open_msg.initial_window_size);
        ASSERT_EQ(131072, *open_msg.max_packet_size);
        *remote_channel_id_ = open_msg.sender_channel;
        open_msg.request.visit(
          [&](const wire::ForwardedTcpipChannelOpenMsg& msg) {
            ASSERT_EQ(address_connected_, msg.address_connected);
            ASSERT_EQ(port_connected_, msg.port_connected);
            ASSERT_EQ("127.0.0.1"s, *msg.originator_address);
            ASSERT_NE(0, *msg.originator_port);
            callbacks_->sendMessage(wire::ChannelOpenConfirmationMsg{
              .recipient_channel = open_msg.sender_channel,
              .sender_channel = local_channel_id_,
              .initial_window_size = wire::ChannelWindowSize,
              .max_packet_size = 131072,
            });
            callbacks_->taskSuccess();
          },
          OR_FAIL);
      },
      OR_FAIL);
  }

  const std::string address_connected_;
  const uint32_t port_connected_;
  const uint32_t local_channel_id_;
  uint32_t* const remote_channel_id_;
};

class WaitForChannelData : public Task {
public:
  WaitForChannelData(uint32_t channel_id, const std::string& expected_data)
      : channel_id_(channel_id),
        expected_data_(expected_data) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        auto view = std::string_view(reinterpret_cast<const char*>(msg.data->data()), msg.data->size());
        if (view.size() >= expected_data_.size()) {
          ASSERT_THAT(view, testing::StartsWith(expected_data_));
          expected_data_.clear();
          callbacks_->taskSuccess();
        } else {
          expected_data_ = absl::StripPrefix(expected_data_, view);
        }
      },
      OR_FAIL);
  }
  absl::Status errorDetails() override {
    return absl::InternalError(fmt::format("expected bytes not received: '{}'", absl::CHexEscape(expected_data_)));
  }
  const uint32_t channel_id_;
  std::string expected_data_;
};

class WaitForChannelCloseByPeer : public Task {
public:
  WaitForChannelCloseByPeer(uint32_t channel_id, uint32_t remote_channel_id, bool allow_eof = true)
      : channel_id_(channel_id),
        remote_channel_id_(remote_channel_id),
        allow_eof_(allow_eof) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelCloseMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        callbacks_->sendMessage(wire::ChannelCloseMsg{
          .recipient_channel = remote_channel_id_,
        });
        callbacks_->taskSuccess();
      },
      [&](const wire::ChannelEOFMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        ASSERT_TRUE(allow_eof_);
      },
      OR_FAIL);
  }
  const uint32_t channel_id_;
  const uint32_t remote_channel_id_;
  const bool allow_eof_;
};

class SendChannelCloseAndWait : public Task {
public:
  SendChannelCloseAndWait(uint32_t channel_id, uint32_t remote_channel_id, bool allow_eof = true)
      : channel_id_(channel_id),
        remote_channel_id_(remote_channel_id),
        allow_eof_(allow_eof) {}
  void start() override {
    callbacks_->sendMessage(wire::ChannelCloseMsg{
      .recipient_channel = remote_channel_id_,
    });
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelCloseMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        callbacks_->taskSuccess();
      },
      [&](const wire::ChannelEOFMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        ASSERT_TRUE(allow_eof_);
      },
      OR_FAIL);
  }
  const uint32_t channel_id_;
  const uint32_t remote_channel_id_;
  const bool allow_eof_;
};

} // namespace Tasks

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec