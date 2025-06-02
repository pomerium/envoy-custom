#include "source/extensions/filters/network/ssh/extension_ping.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class PingExtensionHandlerTest : public testing::Test {
public:
  PingExtensionHandlerTest() {
    transport_ = std::make_unique<testing::StrictMock<MockTransportCallbacks>>();
    handler_ = std::make_unique<PingExtensionHandler>(*transport_);
  }

protected:
  std::unique_ptr<testing::StrictMock<MockTransportCallbacks>> transport_;
  std::unique_ptr<PingExtensionHandler> handler_;
};

TEST_F(PingExtensionHandlerTest, Forward_PingMsg) {
  wire::PingMsg ping{ .data =  "ping data"s };

  {
    wire::Message msg{ping};
    EXPECT_CALL(*transport_, sendMessageToConnection(Eq(wire::Message(wire::PongMsg{ .data = "ping data"s }))))
      .WillOnce(Return(123));
    auto r = handler_->handleMessage(std::move(msg));
    ASSERT_OK(r);
  }

  handler_->enableForward(true);
  {
    wire::Message msg{ping};
    EXPECT_CALL(*transport_, forward(Eq(msg), Eq(EffectiveCommon)));
    auto r = handler_->handleMessage(std::move(msg));
    ASSERT_OK(r);
  }
}

TEST_F(PingExtensionHandlerTest, Forward_PongMsg) {
  wire::PongMsg pong{ .data =  "ping data"s };

  {
    // Should not forward a pong message if forwarding is not enabled.
    wire::Message msg{pong};
    auto r = handler_->handleMessage(std::move(msg));
    ASSERT_OK(r);
  }

  handler_->enableForward(true);
  {
    wire::Message msg{pong};
    EXPECT_CALL(*transport_, forward(Eq(msg), Eq(EffectiveCommon)));
    auto r = handler_->handleMessage(std::move(msg));
    ASSERT_OK(r);
  }
}

TEST_F(PingExtensionHandlerTest, UnhandledMessage) {
  // The handler should not interact with the transport mock at all,
  // regardless of the forwarding mode.
  {
    wire::Message msg{wire::DebugMsg{}};
    ASSERT_OK(handler_->handleMessage(std::move(msg)));
  }

  handler_->enableForward(true);
  {
    wire::Message msg{wire::DebugMsg{}};
    ASSERT_OK(handler_->handleMessage(std::move(msg)));
  }
}

class TestSshMessageDispatcher : public SshMessageDispatcher {
public:
  using SshMessageDispatcher::dispatch_;
};

TEST_F(PingExtensionHandlerTest, Register) {
  TestSshMessageDispatcher d;
  handler_->registerMessageHandlers(d);

  ASSERT_EQ(2, d.dispatch_.size());
  ASSERT_EQ(handler_.get(), d.dispatch_[wire::SshMessageType::Ping]);
  ASSERT_EQ(handler_.get(), d.dispatch_[wire::SshMessageType::Pong]);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
