#pragma once

#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_integration_common.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "absl/synchronization/notification.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using testing::AssertionResult;

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

namespace test {

// These shims allow us to skip including fake_upstream.h in this file, since it is massive
// and adds like 90 seconds to the compile time of any TU that includes it. Modifications to
// just the connection driver should be much quicker to build.

class FakeStreamShim {
public:
  virtual ~FakeStreamShim() = default;
  virtual void startGrpcStream() PURE;
  virtual testing::AssertionResult
  waitForGrpcMessage(Envoy::Event::Dispatcher& client_dispatcher, Protobuf::Message& message,
                     std::chrono::milliseconds timeout) PURE;

  virtual void sendGrpcMessage(const Protobuf::Message& message) PURE;
};

class FakeHttpConnectionShim {
public:
  virtual ~FakeHttpConnectionShim() = default;
  ABSL_MUST_USE_RESULT
  virtual testing::AssertionResult waitForNewStream(
    Envoy::Event::Dispatcher& client_dispatcher, std::unique_ptr<FakeStreamShim>& stream,
    std::chrono::milliseconds timeout) PURE;
  ABSL_MUST_USE_RESULT
  virtual testing::AssertionResult close(Network::ConnectionCloseType close_type, std::chrono::milliseconds timeout) PURE;
};

class FakeUpstreamShim {
public:
  virtual ~FakeUpstreamShim() = default;

  [[nodiscard]]
  virtual testing::AssertionResult waitForHttpConnection(Envoy::Event::Dispatcher& client_dispatcher,
                                                         std::unique_ptr<FakeHttpConnectionShim>& connection,
                                                         std::chrono::milliseconds timeout) PURE;

  [[nodiscard]]
  virtual testing::AssertionResult configureSshUpstream(std::shared_ptr<SshFakeUpstreamHandlerOpts> opts,
                                                        Server::Configuration::ServerFactoryContext& ctx) PURE;

  virtual void cleanup() PURE;
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
                      FakeUpstreamShim& mgmt_upstream);

  void connect();

  testing::AssertionResult
  run(Envoy::Event::Dispatcher::RunType run_type, std::chrono::milliseconds timeout);

  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override;

  AssertionResult disconnect();
  void close();

  void sendMessage(wire::Message&& msg);

  AssertionResult waitForKex();
  AssertionResult waitForDiagnostic(const std::string& message);
  void waitForManagementRequest(Protobuf::Message& req);
  void sendManagementResponse(const Protobuf::Message& resp);
  AssertionResult waitForUserAuth(std::string username = "user", std::string hostname = ""); // empty hostname = internal
  AssertionResult requestReversePortForward(const std::string& address, uint32_t port, uint32_t server_port);
  AssertionResult waitForStatsEvent(pomerium::extensions::ssh::ChannelStatsList* out);
  AssertionResult waitForStatsOnChannelClose(pomerium::extensions::ssh::ChannelStats* out);

  KexResult& kexResult();
  openssh::SSHKey& clientKey();

  template <typename TaskType, typename... Args>
  TaskCallbacksHandle<typename TaskType::input_type, typename TaskType::output_type>
  createTask(Args&&... task_args) {
    auto t = std::make_unique<TaskType>(std::forward<Args>(task_args)...);
    auto cb = std::make_unique<TaskCallbacksImpl>(*this, std::move(t));
    auto& handle = *cb;
    LinkedList::moveIntoList(std::move(cb), active_tasks_);
    return {handle};
  }

  testing::AssertionResult wait(UntypedTaskCallbacksHandle& task);
  bool allTasksComplete() const { return active_tasks_.empty(); }

  std::optional<stream_id_t> serverStreamId() {
    return server_stream_id_;
  }

  std::chrono::milliseconds defaultTimeout() const {
    return default_timeout_;
  }

protected:
  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;

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

  stream_id_t streamId() const override {
    return 42; // unused, except in logs
  }

  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override;

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;

  absl::Status handleMessage(wire::Message&& msg) override;

  // TaskCallbacks
  class TaskCallbacksImpl : public TaskCallbacks,
                            public UntypedTaskCallbacksHandle,
                            public LinkedObject<TaskCallbacksImpl> {
  public:
    TaskCallbacksImpl(SshConnectionDriver& d, std::unique_ptr<UntypedTask> t);
    // TaskCallbacks
    void taskSuccess(std::any output, std::function<void(const std::any&, void*)> apply_fn) override;
    void taskFailure(absl::Status stat) override;
    void setTimeout(std::chrono::milliseconds timeout, const std::string& name) override;
    void setTimeout(std::chrono::milliseconds timeout, std::function<void()> cb) override;

    void sendMessage(wire::Message&& msg) override;
    void loop(std::chrono::milliseconds interval, std::function<void()> cb) override;

    // TaskCallbacksHandle
    UntypedTaskCallbacksHandle& start(std::any input) override;

    UntypedTaskCallbacksHandle& then(UntypedTaskCallbacksHandle& next) override;
    UntypedTaskCallbacksHandle& saveOutput(void* output_ptr) override;

    struct token_t {
      absl::AnyInvocable<void()> on_destroyed;
      ~token_t() {
        if (on_destroyed) {
          on_destroyed();
        }
      }
    };
    static void setTokenRecursive(TaskCallbacksImpl& h, const std::shared_ptr<token_t>& token);

    SshConnectionDriver& parent_;
    std::unique_ptr<UntypedTask> task_;
    std::vector<UntypedTaskCallbacksHandle*> start_after_;
    std::vector<void*> output_ptrs_;
    bool started_{};
    bool wait_called_{};

    std::shared_ptr<token_t> token_ = std::make_shared<token_t>();
    std::weak_ptr<token_t> weak_token_{token_};
    Envoy::Event::TimerPtr timeout_timer_;
    Envoy::Event::TimerPtr loop_;
  };

  class CodecCallbacks : public SshConnectionDriverCodecCallbacks {
  public:
    explicit CodecCallbacks(Network::ClientConnection& client_connection)
        : client_connection_(client_connection) {}
    void onDecodingFailure(absl::string_view reason = {}) override;
    void writeToConnection(Buffer::Instance& buffer) override;

    bool expect_decoding_failure_{};
    Network::ClientConnection& client_connection_;
  };

  Envoy::Network::ReadFilterCallbacks* read_filter_callbacks_{nullptr};
  Network::ClientConnectionPtr client_connection_;

  absl::Notification on_kex_completed_;
  std::shared_ptr<KexResult> kex_result_;

  std::unique_ptr<CodecCallbacks> codec_callbacks_;

  FakeUpstreamShim& mgmt_upstream_;
  std::unique_ptr<FakeHttpConnectionShim> mgmt_connection_;
  std::unique_ptr<FakeStreamShim> mgmt_stream_;
  std::optional<stream_id_t> server_stream_id_;

  std::list<std::unique_ptr<TaskCallbacksImpl>> active_tasks_;
  std::list<std::unique_ptr<TaskCallbacksImpl>> completed_tasks_;

  std::chrono::milliseconds default_timeout_;

private:
  bool expect_remote_close_{};
  bool disconnected_{};
  bool closed_{};
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec