#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_common.h"
#include "test/test_common/test_time_system.h"
#include "gtest/gtest.h"
#include <chrono>

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
  default_timeout_ = isDebuggerAttached()
                       ? std::chrono::hours(10)
                       : std::chrono::seconds(10);
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
  if (!disconnected_) {
    codec_callbacks_->expect_decoding_failure_ = true;
    sendMessage(wire::DisconnectMsg{
      .reason_code = SSH2_DISCONNECT_BY_APPLICATION,
    });
    // Run the event loop to process the disconnect message.
    while (!disconnected_) {
      if (auto res = run(Envoy::Event::Dispatcher::RunType::NonBlock, default_timeout_); !res) {
        return res;
      }
    }
  }
  close();
  return AssertionResult(true);
}

void SshConnectionDriver::close() {
  if (!closed_) {
    auto& dispatcher = client_connection_->dispatcher();
    closed_ = true;
    client_connection_->close(Network::ConnectionCloseType::AbortReset);
    client_connection_.reset(); // IMPORTANT: client_connection_ holds a shared_ptr to this
    ASSERT(disconnected_ == true);
    dispatcher.clearDeferredDeleteList();
  }
}

void SshConnectionDriver::sendMessage(wire::Message&& msg) {
  if (auto r = sendMessageToConnection(std::move(msg)); !r.ok()) {
    terminate(r.status());
  }
}

AssertionResult SshConnectionDriver::waitForKex() {
  auto start = std::chrono::system_clock::now();
  while ((client_connection_->connecting() || client_connection_->state() == Network::Connection::State::Open) &&
         !on_kex_completed_.HasBeenNotified()) {
    if ((std::chrono::system_clock::now() - start) > default_timeout_) {
      return AssertionResult(false) << "timed out";
    }
    auto res = run(Envoy::Event::Dispatcher::RunType::NonBlock, default_timeout_);
    if (!res) {
      return res;
    }
  }

  auto res = mgmt_upstream_.waitForHttpConnection(*connectionDispatcher(), mgmt_connection_, default_timeout_);
  if (!res) {
    return res;
  }
  res = mgmt_connection_->waitForNewStream(*connectionDispatcher(), mgmt_stream_, default_timeout_);
  if (!res) {
    return res;
  }
  mgmt_stream_->startGrpcStream();
  pomerium::extensions::ssh::ClientMessage connected;
  res = mgmt_stream_->waitForGrpcMessage(*connectionDispatcher(), connected, default_timeout_);
  if (!res) {
    return res;
  }
  auto event = connected.event().downstream_connected();
  server_stream_id_ = event.stream_id();
  return AssertionResult(!testing::Test::HasFailure());
}

void SshConnectionDriver::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::Connected ||
      event == Network::ConnectionEvent::ConnectedZeroRtt) {
    version_exchanger_->writeVersion(server_version_);
    return;
  }
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    disconnected_ = true;
    // Disconnect the management server after the server transport is done, otherwise the server
    // transport will trigger an error
    if (mgmt_connection_ != nullptr) {
      EXPECT_TRUE(mgmt_connection_->close(Network::ConnectionCloseType::FlushWrite, default_timeout_));
    }
  }
}

AssertionResult SshConnectionDriver::waitForDiagnostic(const std::string& message) {
  ClientMessage clientMsg;
  Envoy::Event::TestTimeSystem::RealTimeBound bound(defaultTimeout());
  while (!testing::Test::HasFailure() && bound.withinBound()) {
    waitForManagementRequest(clientMsg);
    if (!clientMsg.event().channel_event().has_internal_channel_closed()) {
      continue;
    }
    for (auto diag : clientMsg.event().channel_event().internal_channel_closed().diagnostics()) {
      if (diag.message().contains(message)) {
        return AssertionResult(true);
      }
    }
    return AssertionResult(false) << "internal_channel_close received, but did not contain the expected diagnostic";
  }
  return AssertionResult(false) << "timed out waiting for diagnostic";
}

AssertionResult SshConnectionDriver::waitForStatsOnChannelClose(pomerium::extensions::ssh::ChannelStats* out) {
  ClientMessage clientMsg;
  Envoy::Event::TestTimeSystem::RealTimeBound bound(defaultTimeout());
  while (!testing::Test::HasFailure() && bound.withinBound()) {
    waitForManagementRequest(clientMsg);
    if (!clientMsg.event().channel_event().internal_channel_closed().has_stats()) {
      continue;
    }
    *out = clientMsg.event().channel_event().internal_channel_closed().stats();
    return AssertionResult(true);
  }
  return AssertionResult(false) << "timed out waiting for channel close event";
}

void SshConnectionDriver::waitForManagementRequest(Protobuf::Message& req) {
  auto res = mgmt_stream_->waitForGrpcMessage(
    *connectionDispatcher(), req, default_timeout_);
  if (!res) {
    terminate(absl::InternalError("waitForManagementRequest failed"));
  }
}

void SshConnectionDriver::sendManagementResponse(const Protobuf::Message& resp) {
  mgmt_stream_->sendGrpcMessage(resp);
}

AssertionResult SshConnectionDriver::waitForUserAuth(std::string username, bool internal) {
  if (auto res = wait(createTask<Tasks::RequestUserAuthService>().start()); !res) {
    return res;
  }

  wire::UserAuthRequestMsg req;
  req.username = username;
  req.service_name = "ssh-connection";

  auto& key = clientKey();
  wire::PubKeyUserAuthRequestMsg pubkeyReq{
    .has_signature = true,
    .public_key_alg = key.signatureAlgorithmsForKeyType()[0],
    .public_key = key.toPublicKeyBlob(),
  };
  // compute signature
  Envoy::Buffer::OwnedImpl buf;
  wire::write_opt<wire::LengthPrefixed>(buf, kexResult().session_id);
  constexpr static wire::field<std::string, wire::LengthPrefixed> method_name =
    std::string(wire::PubKeyUserAuthRequestMsg::submsg_key);
  EXPECT_OK(wire::encodeMsg(buf, req.type,
                            req.username,
                            req.service_name,
                            method_name,
                            pubkeyReq.has_signature,
                            pubkeyReq.public_key_alg,
                            pubkeyReq.public_key));
  auto sig = key.sign(wire::flushTo<bytes>(buf), pubkeyReq.public_key_alg);
  EXPECT_OK(sig);
  pubkeyReq.signature = *sig;
  req.request = std::move(pubkeyReq);

  auto th = createTask<Tasks::WaitForUserAuthSuccess>().start();
  sendMessage(std::move(req));

  ClientMessage clientMsg;
  waitForManagementRequest(clientMsg);
  EXPECT_EQ("publickey", clientMsg.auth_request().auth_method());
  pomerium::extensions::ssh::FilterMetadata filterMetadata;
  filterMetadata.set_stream_id(streamId());
  // Only the stream id is set here, not channel id.
  // TODO: maybe refactor this api to be less confusing

  if (internal) {
    ServerMessage serverMsg;
    (*serverMsg.mutable_auth_response()
        ->mutable_allow()
        ->mutable_internal()
        ->mutable_set_metadata()
        ->mutable_typed_filter_metadata())["com.pomerium.ssh"]
      .PackFrom(filterMetadata);
    sendManagementResponse(serverMsg);
  } else {
    PANIC("unimplemented");
  }

  return wait(th);
}
AssertionResult SshConnectionDriver::requestReversePortForward(const std::string& address, uint32_t port, uint32_t server_port) {
  sendMessage(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{
      .remote_address = address,
      .remote_port = port,
    },
  });
  ClientMessage clientMsg;
  waitForManagementRequest(clientMsg);
  ServerMessage serverMsg;
  serverMsg.mutable_global_request_response()
    ->set_success(true);
  serverMsg.mutable_global_request_response()
    ->mutable_tcpip_forward_response()
    ->set_server_port(server_port);

  auto th = createTask<Tasks::WaitForGlobalRequestSuccess<wire::TcpipForwardResponseMsg>>().start();

  sendManagementResponse(serverMsg);

  return wait(th);
}

AssertionResult SshConnectionDriver::waitForStatsEvent(pomerium::extensions::ssh::ChannelStats* out) {
  Envoy::Event::TestTimeSystem::RealTimeBound bound(std::chrono::seconds(1));
  while (!testing::Test::HasFailure() && bound.withinBound()) {
    pomerium::extensions::ssh::ClientMessage connected;
    auto res = mgmt_stream_->waitForGrpcMessage(*connectionDispatcher(), connected, std::chrono::milliseconds(100));
    if (!res) {
      return res;
    }
    if (!connected.event().channel_event().internal_channel_stats().has_stats()) {
      continue;
    }
    *out = connected.event().channel_event().internal_channel_stats().stats();
    return AssertionResult(true);
  }
  return AssertionResult(false) << "timed out waiting for stats event";
}

void SshConnectionDriver::TaskCallbacksImpl::loop(std::chrono::milliseconds interval, std::function<void()> cb) {
  loop_ = parent_.connectionDispatcher()->createTimer([this, interval, cb] mutable {
    if (testing::Test::HasFailure()) {
      return;
    }
    // Schedule the loop again *before* running the callback; it is expected that taskSuccess or
    // taskFailure will be called from inside the callback, and those functions will cancel the
    // next scheduled invocation.
    loop_->enableTimer(interval);
    cb();
    // If the task completed, uninstall the message middleware. This otherwise only happens
    // after onMessageReceived().
    if (!loop_->enabled()) {
      ENVOY_LOG_MISC(debug, "task completed in loop, uninstalling middleware");
      parent_.uninstallMiddleware(task_.get());
    }
  });
  loop_->enableTimer({}); // start right away
}

testing::AssertionResult SshConnectionDriver::wait(UntypedTaskCallbacksHandle& handle) {
  auto& handle_impl = dynamic_cast<TaskCallbacksImpl&>(handle);
  RELEASE_ASSERT(handle_impl.started_, "test bug: wait() called on unstarted task");
  RELEASE_ASSERT(!handle_impl.wait_called_, "test bug: wait() called twice on the same task handle");
  handle_impl.wait_called_ = true;

  bool timed_out{};
  auto timeout = connectionDispatcher()->createTimer([this, &timed_out] {
    timed_out = true;
    connectionDispatcher()->exit();
  });
  // Set the wait timeout higher than the task timeout to prevent the two timeouts racing. The task
  // should time out first
  timeout->enableTimer(default_timeout_ + default_timeout_ / 2);

  auto weak_token = std::weak_ptr{handle_impl.weak_token_};
  {
    auto shared_token = weak_token.lock();
    if (shared_token == nullptr) {
      // task already exited
      return AssertionResult(!testing::Test::HasFailure());
    }
    // Hold a reference to the shared token and only release it while the dispatcher is running.
    connectionDispatcher()->post([this, shared_token = std::move(shared_token)] {
      shared_token->on_destroyed = [this] {
        connectionDispatcher()->exit();
      };
    });
  }
  while (true) {
    connectionDispatcher()->run(Envoy::Event::Dispatcher::RunType::RunUntilExit);
    if (weak_token.expired()) {
      timeout->disableTimer();
      return AssertionResult(!testing::Test::HasFailure());
    }
    if (timed_out) {
      return AssertionResult(false) << "timed out waiting for tasks to be completed";
    }
    // spurious wakeup
  }
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
  task_->callbacks_ = this;
  task_->stream_id_ = *parent_.server_stream_id_;
  task_->default_timeout_ = parent_.default_timeout_;
}

void SshConnectionDriver::TaskCallbacksImpl::taskSuccess(std::any output, std::function<void(const std::any&, void*)> apply_fn) {
  RELEASE_ASSERT(!testing::Test::HasFailure(), "");
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  if (loop_ != nullptr) {
    loop_->disableTimer();
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
  if (loop_ != nullptr) {
    loop_->disableTimer();
  }
  RELEASE_ASSERT(inserted(), "");
  if (!testing::Test::HasFailure()) {
    ADD_FAILURE() << statusToString(stat);
  }
  moveBetweenLists(parent_.active_tasks_, parent_.completed_tasks_);
  // clear the token on any future tasks which will not run
  setTokenRecursive(*this, nullptr);
}

KexResult& SshConnectionDriver::kexResult() {
  return *kex_result_;
}

openssh::SSHKey& SshConnectionDriver::clientKey() {
  return *host_key_;
}

void SshConnectionDriver::TaskCallbacksImpl::setTimeout(std::chrono::milliseconds timeout, const std::string& name) {
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  timeout_timer_ = parent_.connectionDispatcher()->createTimer([this, name] {
    taskFailure(absl::DeadlineExceededError("task timed out: " + name));
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
  task_->startInternalUntyped(input);

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
  if (h.token_ != token) {
    h.token_ = token;
    h.weak_token_ = h.token_;
  }
  for (auto* next : h.start_after_) {
    setTokenRecursive(dynamic_cast<TaskCallbacksImpl&>(*next), token);
  }
}

void SshConnectionDriver::CodecCallbacks::onDecodingFailure(absl::string_view reason) {
  if (!expect_decoding_failure_) {
    FAIL() << reason;
  }
  client_connection_.close(Network::ConnectionCloseType::NoFlush, reason);
  client_connection_.dispatcher().exit();
}

void SshConnectionDriver::CodecCallbacks::writeToConnection(Buffer::Instance& buffer) {
  client_connection_.write(buffer, false);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec