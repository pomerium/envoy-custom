#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_time_system.h"
#include "test/test_common/utility.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {
SshConnectionDriver::SshConnectionDriver(Network::ClientConnectionPtr client_connection,
                                         Server::Configuration::ServerFactoryContext& context,
                                         std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                         FakeUpstreamShim& mgmt_upstream)
    : TransportBase(context, config, *this),
      client_connection_(std::move(client_connection)),
      mgmt_upstream_(mgmt_upstream) {
  server_version_ = "SSH-2.0-SshConnectionDriver";
}

void SshConnectionDriver::connect() {
  codec_callbacks_ = std::make_unique<CodecCallbacks>(*client_connection_);
  setCodecCallbacks(*codec_callbacks_);
  client_connection_->addReadFilter(shared_from_this());
  client_connection_->connect();
}

testing::AssertionResult
SshConnectionDriver::run(Envoy::Event::Dispatcher::RunType run_type,
                         std::chrono::milliseconds timeout) {
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

Envoy::OptRef<Envoy::Event::Dispatcher> SshConnectionDriver::connectionDispatcher() const {
  return client_connection_->dispatcher();
}

AssertionResult SshConnectionDriver::disconnect() {
  codec_callbacks_->expect_decoding_failure_ = true;
  sendMessage(wire::DisconnectMsg{
    .reason_code = 11,
  });
  // Run the event loop to process the disconnect message.
  if (auto res = run(Envoy::Event::Dispatcher::RunType::RunUntilExit, defaultTimeout()); !res) {
    return res;
  }
  client_connection_->close(Network::ConnectionCloseType::AbortReset);
  client_connection_.reset(); // IMPORTANT: client_connection_ holds a shared_ptr to this
  return AssertionResult(true);
}

void SshConnectionDriver::sendMessage(wire::Message&& msg) {
  if (auto r = sendMessageToConnection(std::move(msg)); !r.ok()) {
    terminate(r.status());
  }
}

AssertionResult SshConnectionDriver::waitForKex(std::chrono::milliseconds timeout) {
  auto start = std::chrono::system_clock::now();
  while ((client_connection_->connecting() || client_connection_->state() == Network::Connection::State::Open) &&
         !on_kex_completed_.HasBeenNotified()) {
    if ((std::chrono::system_clock::now() - start) > timeout) {
      return AssertionResult(false) << "timed out";
    }
    auto res = run(Envoy::Event::Dispatcher::RunType::NonBlock, defaultTimeout());
    if (!res) {
      return res;
    }
  }

  auto res = mgmt_upstream_.waitForHttpConnection(*connectionDispatcher(), mgmt_connection_, timeout);
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

void SshConnectionDriver::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::Connected ||
      event == Network::ConnectionEvent::ConnectedZeroRtt) {
    version_exchanger_->writeVersion(server_version_);
    return;
  }
  if (event == Network::ConnectionEvent::RemoteClose) {
    EXPECT_TRUE(expect_remote_close_) << "unexpected remote close";
  }
  connectionDispatcher()->exit();

  // Disconnect the management server after the server transport is done, otherwise the server
  // transport will trigger an error
  if (mgmt_connection_ != nullptr) {
    EXPECT_TRUE(mgmt_connection_->close(Network::ConnectionCloseType::FlushWrite, defaultTimeout()));
  }
}

void test::SshConnectionDriver::TaskCallbacksImpl::waitForManagementRequest(Protobuf::Message& req) {
  auto res = parent_.mgmt_stream_->waitForGrpcMessage(
    *parent_.connectionDispatcher(), req, defaultTimeout());
  if (!res) {
    parent_.terminate(absl::InternalError("waitForManagementRequest failed"));
  }
}

void test::SshConnectionDriver::TaskCallbacksImpl::sendManagementResponse(const Protobuf::Message& resp) {
  parent_.mgmt_stream_->sendGrpcMessage(resp);
}

testing::AssertionResult SshConnectionDriver::wait(UntypedTaskCallbacksHandle& handle, std::chrono::milliseconds timeout) {
  if (!dynamic_cast<TaskCallbacksImpl&>(handle).started_) {
    PANIC("test bug: wait() called on unstarted task");
  }
  // Logic here copied from waitForWithDispatcherRun
  absl::MutexLock lock(&lock_);
  auto& time_system =
    dynamic_cast<Envoy::Event::TestTimeSystem&>(connectionDispatcher()->timeSource());
  Envoy::Event::TestTimeSystem::RealTimeBound bound(timeout);
  std::weak_ptr<void> weak_token = dynamic_cast<TaskCallbacksImpl&>(handle).token_;
  auto condition = [&weak_token] { return weak_token.expired(); };
  while (bound.withinBound()) {
    // Wake up periodically to run the client dispatcher.
    if (time_system.waitFor(lock_, absl::Condition(&condition), 5ms * TIMEOUT_FACTOR)) {
      return AssertionResult(!testing::Test::HasFailure());
    }
    connectionDispatcher()->run(Envoy::Event::Dispatcher::RunType::NonBlock);
  }
  return AssertionResult(false) << "timed out waiting for tasks to be completed";
}

void SshConnectionDriver::onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) {
  TransportBase::onKexCompleted(kex_result, initial_kex);
  kex_result_ = kex_result;
  on_kex_completed_.Notify();
}

void SshConnectionDriver::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
}

absl::Status SshConnectionDriver::handleMessage(wire::Message&& msg) {
  expect_remote_close_ = true;
  auto dc = msg.message.get<wire::DisconnectMsg>();
  auto desc = *dc.description;
  return absl::CancelledError(fmt::format("received disconnect: {}{}{}",
                                          openssh::disconnectCodeToString(*dc.reason_code),
                                          desc.empty() ? "" : ": ", desc));
}

SshConnectionDriver::TaskCallbacksImpl::TaskCallbacksImpl(SshConnectionDriver& d, std::unique_ptr<UntypedTask> t)
    : parent_(d),
      task_(std::move(t)) {
  task_->setTaskCallbacks(*this, parent_.streamId());
}

void SshConnectionDriver::TaskCallbacksImpl::taskSuccess(std::any output, std::function<void(const std::any&, void*)> apply_fn) {
  RELEASE_ASSERT(!testing::Test::HasFailure(), "");
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  RELEASE_ASSERT(inserted(), "");
  for (void* ptr : output_ptrs_) {
    apply_fn(output, ptr);
  }
  for (auto* next : start_after_) {
    next->start(output);
  }
  moveBetweenLists(parent_.active_tasks_, parent_.completed_tasks_);
  token_.reset();
}

void SshConnectionDriver::TaskCallbacksImpl::taskFailure(absl::Status stat) {
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  RELEASE_ASSERT(inserted(), "");
  if (!testing::Test::HasFailure()) {
    ADD_FAILURE() << statusToString(stat);
  }
  moveBetweenLists(parent_.active_tasks_, parent_.completed_tasks_);
  token_.reset();
}

KexResult& SshConnectionDriver::TaskCallbacksImpl::kexResult() {
  return *parent_.kex_result_;
}

openssh::SSHKey& SshConnectionDriver::TaskCallbacksImpl::clientKey() {
  return *parent_.host_key_;
}

void SshConnectionDriver::TaskCallbacksImpl::setTimeout(std::chrono::milliseconds timeout) {
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  timeout_timer_ = parent_.connectionDispatcher()->createTimer([this] {
    taskFailure(absl::DeadlineExceededError("task timed out"));
  });
  timeout_timer_->enableTimer(timeout);
}

void SshConnectionDriver::TaskCallbacksImpl::sendMessage(wire::Message&& msg) {
  parent_.sendMessage(std::move(msg));
}

UntypedTaskCallbacksHandle& SshConnectionDriver::TaskCallbacksImpl::start(std::any input) {
  started_ = true;
  // propagate our token to all dependent tasks
  setTokenRecursive(*this, token_);
  parent_.installMiddleware(task_.get());
  parent_.connectionDispatcher()->post([this, input] {
    task_->startInternalUntyped(input);
  });
  return *this;
}

UntypedTaskCallbacksHandle& SshConnectionDriver::TaskCallbacksImpl::then(UntypedTaskCallbacksHandle& next) {
  start_after_.push_back(&next);
  return *this;
}

UntypedTaskCallbacksHandle& SshConnectionDriver::TaskCallbacksImpl::saveOutput(void* output_ptr) {
  output_ptrs_.push_back(output_ptr);
  return *this;
}

void SshConnectionDriver::TaskCallbacksImpl::setTokenRecursive(TaskCallbacksImpl& h, const std::shared_ptr<token_t>& token) {
  if (h.token_.get() != token.get()) {
    h.token_ = token;
  }
  for (auto* next : h.start_after_) {
    setTokenRecursive(dynamic_cast<TaskCallbacksImpl&>(*next), token);
  }
}

void SshConnectionDriver::CodecCallbacks::onDecodingFailure(absl::string_view reason) {
  if (!expect_decoding_failure_) {
    FAIL() << reason;
  }
  client_connection_.close(Network::ConnectionCloseType::FlushWrite, reason);
}

void SshConnectionDriver::CodecCallbacks::writeToConnection(Buffer::Instance& buffer) {
  client_connection_.write(buffer, false);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec