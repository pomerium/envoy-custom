#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_time_system.h"
#include "test/test_common/utility.h"

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

AssertionResult SshConnectionDriver::waitAllTasksComplete() {
  // Logic here copied from waitForWithDispatcherRun
  absl::MutexLock lock(&lock_);
  auto& time_system =
    dynamic_cast<Envoy::Event::TestTimeSystem&>(connectionDispatcher()->timeSource());
  Envoy::Event::TestTimeSystem::RealTimeBound bound(defaultTimeout());
  auto condition = [this] { return active_tasks_.empty(); };
  while (bound.withinBound()) {
    // Wake up periodically to run the client dispatcher.
    if (time_system.waitFor(lock_, absl::Condition(&condition), 5ms * TIMEOUT_FACTOR)) {
      return AssertionResult(!testing::Test::HasFailure());
    }
    connectionDispatcher()->run(Envoy::Event::Dispatcher::RunType::NonBlock);
  }
  return AssertionResult(false) << "timed out waiting for tasks to be completed";
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
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec