#pragma once

#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
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
  ABSL_MUST_USE_RESULT
  virtual testing::AssertionResult waitForHttpConnection(
    Envoy::Event::Dispatcher& client_dispatcher, std::unique_ptr<FakeHttpConnectionShim>& connection,
    std::chrono::milliseconds timeout) PURE;
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
                      FakeUpstreamShim& mgmt_upstream);

  void connect();

  testing::AssertionResult
  run(Envoy::Event::Dispatcher::RunType run_type, std::chrono::milliseconds timeout);

  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override;

  AssertionResult disconnect();

  void sendMessage(wire::Message&& msg);

  AssertionResult waitForKex(std::chrono::milliseconds timeout = defaultTimeout());

  template <typename TaskType, typename... Args>
  TaskCallbacksHandle<typename TaskType::input_type, typename TaskType::output_type>
  createTask(Args&&... task_args) {
    auto t = std::make_unique<TaskType>(std::forward<Args>(task_args)...);
    auto cb = std::make_unique<TaskCallbacksImpl>(*this, std::move(t));
    auto& handle = *cb;
    LinkedList::moveIntoList(std::move(cb), active_tasks_);
    return {handle};
  }

  testing::AssertionResult wait(UntypedTaskCallbacksHandle& task, std::chrono::milliseconds timeout = defaultTimeout());

  stream_id_t streamId() const override {
    ASSERT(stream_id_ != 0);
    return stream_id_;
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

  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override {
    TransportBase::onKexCompleted(kex_result, initial_kex);
    kex_result_ = kex_result;
    on_kex_completed_.Notify();
  }

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override {
    dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
  }

  absl::Status handleMessage(wire::Message&& msg) override {
    expect_remote_close_ = true;
    auto dc = msg.message.get<wire::DisconnectMsg>();
    auto desc = *dc.description;
    return absl::CancelledError(fmt::format("received disconnect: {}{}{}",
                                            openssh::disconnectCodeToString(*dc.reason_code),
                                            desc.empty() ? "" : ": ", desc));
  }

  // TaskCallbacks
  class TaskCallbacksImpl : public TaskCallbacks,
                            public UntypedTaskCallbacksHandle,
                            public LinkedObject<TaskCallbacksImpl> {
  public:
    TaskCallbacksImpl(SshConnectionDriver& d, std::unique_ptr<UntypedTask> t)
        : parent_(d),
          task_(std::move(t)) {
      task_->setTaskCallbacks(*this, parent_.streamId());
    }
    // TaskCallbacks
    void taskSuccess(std::any output, std::function<void(const std::any&, void*)> apply_fn) override {
      ASSERT(!testing::Test::HasFailure());
      if (timeout_timer_ != nullptr) {
        timeout_timer_->disableTimer();
      }
      ASSERT(inserted());
      for (void* ptr : output_ptrs_) {
        apply_fn(output, ptr);
      }
      for (auto* next : start_after_) {
        next->start(output);
      }
      moveBetweenLists(parent_.active_tasks_, parent_.completed_tasks_);
      token_.reset();
    }
    void taskFailure(absl::Status stat) override {
      if (timeout_timer_ != nullptr) {
        timeout_timer_->disableTimer();
      }
      ASSERT(inserted());
      ADD_FAILURE() << statusToString(stat);
      moveBetweenLists(parent_.active_tasks_, parent_.completed_tasks_);
      token_.reset();
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
    void waitForManagementRequest(Protobuf::Message& req) override;
    void sendManagementResponse(const Protobuf::Message& resp) override;

    // TaskCallbacksHandle
    UntypedTaskCallbacksHandle& start(std::any input) override {
      started_ = true;
      parent_.installMiddleware(task_.get());
      parent_.connectionDispatcher()->post([this, input] {
        task_->startInternalUntyped(input);
      });
      return *this;
    }

    UntypedTaskCallbacksHandle& then(UntypedTaskCallbacksHandle& next) override {
      start_after_.push_back(&next);
      dynamic_cast<TaskCallbacksImpl&>(next).token_ = token_;
      return *this;
    }
    UntypedTaskCallbacksHandle& saveOutput(void* output_ptr) override {
      output_ptrs_.push_back(output_ptr);
      return *this;
    }

    SshConnectionDriver& parent_;
    std::unique_ptr<UntypedTask> task_;
    std::any task_output_;
    std::vector<UntypedTaskCallbacksHandle*> start_after_;
    std::vector<void*> output_ptrs_;
    bool started_{};
    struct token_t {
      ~token_t() { parent_.parent_.connectionDispatcher()->exit(); }
      TaskCallbacksImpl& parent_;
    };
    std::shared_ptr<token_t> token_ = std::make_shared<token_t>(*this);
    Envoy::Event::TimerPtr timeout_timer_;
  };

  class CodecCallbacks : public SshConnectionDriverCodecCallbacks {
  public:
    explicit CodecCallbacks(Network::ClientConnection& client_connection)
        : client_connection_(client_connection) {}
    void onDecodingFailure(absl::string_view reason = {}) override {
      if (!expect_decoding_failure_) {
        FAIL() << reason;
      }
      client_connection_.close(Network::ConnectionCloseType::FlushWrite, reason);
    }

    void writeToConnection(Buffer::Instance& buffer) override {
      client_connection_.write(buffer, false);
    }

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

  stream_id_t stream_id_;

  std::list<std::unique_ptr<TaskCallbacksImpl>> active_tasks_;
  std::list<std::unique_ptr<TaskCallbacksImpl>> completed_tasks_;

private:
  absl::Mutex lock_;
  bool expect_remote_close_{};
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec