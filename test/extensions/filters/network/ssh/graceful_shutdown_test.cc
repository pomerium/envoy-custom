
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_common.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class GracefulShutdownIntegrationTest : public testing::Test,
                                        public SshIntegrationTest,
                                        public testing::WithParamInterface<Network::Address::IpVersion> {
public:
  GracefulShutdownIntegrationTest()
      : SshIntegrationTest({"upstream1"}, GetParam()) {}

  void SetUp() override {
    initialize();

    EXPECT_CALL(channel_recv_, Call(MSG(wire::ChannelDataMsg, _)));
    ASSERT_TRUE(configureSshUpstream(SshFakeUpstreamHandlerOpts{
      .on_channel_open_request = [this](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
        return [&](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
          channel_recv_.Call(auto(msg));
          return msg.visit(
            [&](wire::ChannelDataMsg& msg) {
              callbacks.sendMessageLocal(wire::ChannelDataMsg{
                .recipient_channel = callbacks.channelId(),
                .data = msg.data,
              });
              return absl::OkStatus();
            },
            [&](wire::ChannelCloseMsg&) {
              callbacks.sendMessageLocal(wire::ChannelCloseMsg{
                .recipient_channel = callbacks.channelId(),
              });
              return absl::OkStatus();
            },
            [&](auto&) {
              return absl::OkStatus();
            });
        };
      },
    }));

    driver_ = makeSshConnectionDriver();
    driver_->connect();

    ASSERT_TRUE(driver_->waitForKex());
    ASSERT_TRUE(driver_->waitForUserAuth("user", "upstream1"));

    // Create a channel and make sure it is functional
    ASSERT_TRUE(driver_->wait(
      driver_->createTask<Tasks::OpenSessionChannel>(1)
        .saveOutput(&channel_)
        .then(driver_->createTask<Tasks::SendChannelData>("testing")
                .then(driver_->createTask<Tasks::WaitForChannelData>("testing")))
        .start()));
  }

  void TearDown() override {
    if (driver_) {
      EXPECT_TRUE(driver_->disconnect());
    }
    cleanup();
  }

  testing::StrictMock<testing::MockFunction<void(wire::Message&&)>> channel_recv_;
  SshFakeUpstreamHandlerOpts opts_;
  std::shared_ptr<SshConnectionDriver> driver_;
  Tasks::Channel channel_;
};

TEST_P(GracefulShutdownIntegrationTest, ServerDrain) {
  absl::Notification drainComplete;
  auto th = driver_->createTask<Tasks::WaitForChannelCloseByPeer>()
              .then(driver_->createTask<Tasks::WaitForDisconnectWithError>("server shutting down"))
              .start(channel_);
  EXPECT_CALL(channel_recv_, Call(MSG(wire::ChannelCloseMsg, _)));
  test_server_->server().dispatcher().post([this, &drainComplete] {
    test_server_->server().drainManager().startDrainSequence(Network::DrainDirection::All, [&drainComplete] {
      drainComplete.Notify();
    });
  });
  ASSERT_TRUE(driver_->wait(th));
  ASSERT_TRUE(drainComplete.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_P(GracefulShutdownIntegrationTest, ServerShutdown) {
  auto th = driver_->createTask<Tasks::WaitForChannelCloseByPeer>()
              .then(driver_->createTask<Tasks::WaitForDisconnectWithError>("server shutting down"))
              .start(channel_);
  EXPECT_CALL(channel_recv_, Call(MSG(wire::ChannelCloseMsg, _)));
  test_server_->server().dispatcher().post([this] {
    test_server_->server().shutdown();
  });
  ASSERT_TRUE(driver_->wait(th));
}

TEST_P(GracefulShutdownIntegrationTest, ServerShutdownThenDrain) {
  auto th = driver_->createTask<Tasks::WaitForChannelCloseByPeer>()
              .then(driver_->createTask<Tasks::WaitForDisconnectWithError>("server shutting down"))
              .start(channel_);
  EXPECT_CALL(channel_recv_, Call(MSG(wire::ChannelCloseMsg, _)));
  absl::Notification drainComplete;
  test_server_->server().dispatcher().post([this, &drainComplete] {
    test_server_->server().shutdown();
    test_server_->server().drainManager().startDrainSequence(Network::DrainDirection::All, [&drainComplete] {
      drainComplete.Notify();
    });
  });
  ASSERT_TRUE(driver_->wait(th));
  ASSERT_FALSE(drainComplete.WaitForNotificationWithTimeout(absl::Milliseconds(100)));
}

TEST_P(GracefulShutdownIntegrationTest, ServerShutdownTwice) {
  auto th = driver_->createTask<Tasks::WaitForChannelCloseByPeer>()
              .then(driver_->createTask<Tasks::WaitForDisconnectWithError>("server shutting down"))
              .start(channel_);
  EXPECT_CALL(channel_recv_, Call(MSG(wire::ChannelCloseMsg, _)));
  test_server_->server().dispatcher().post([this] {
    test_server_->server().shutdown();
    test_server_->server().shutdown();
  });
  ASSERT_TRUE(driver_->wait(th));
}

class WaitForChannelCloseAndDoNotReply : public Task<Tasks::Channel, Tasks::Channel> {
public:
  void start(Tasks::Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_, "WaitForChannelCloseAndDoNotReply");
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelCloseMsg&) {
        taskSuccess(channel_);
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  Tasks::Channel channel_{};
};

TEST_P(GracefulShutdownIntegrationTest, ServerShutdown_CloseTimeout) {
  auto th = driver_->createTask<WaitForChannelCloseAndDoNotReply>()
              .then(driver_->createTask<Tasks::WaitForDisconnectWithError>("timed out waiting for channel close response from Downstream"))
              .start(channel_);
  EXPECT_CALL(channel_recv_, Call(MSG(wire::ChannelCloseMsg, _)))
    .Times(testing::AtMost(1)); // 0 or 1 times, timing-dependent. Not relevant for this test
  test_server_->server().dispatcher().post([this] {
    test_server_->server().shutdown();
  });
  ASSERT_TRUE(driver_->wait(th));
}

INSTANTIATE_TEST_SUITE_P(GracefulShutdown, GracefulShutdownIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec