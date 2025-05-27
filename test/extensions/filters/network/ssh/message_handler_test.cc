#include "source/extensions/filters/network/ssh/message_handler.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class TestMessageDispatcher : public SshMessageDispatcher {
public:
  using SshMessageDispatcher::dispatch;
  using SshMessageDispatcher::dispatch_;
  using SshMessageDispatcher::middlewares_;
};

TEST(SshMessageDispatcherTest, RegisterHandler) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  TestMessageDispatcher dispatcher;
  EXPECT_NO_THROW(dispatcher.registerHandler(wire::SshMessageType::KexInit, &handler1));
  EXPECT_EQ(1, dispatcher.dispatch_.size());
  EXPECT_EQ(dispatcher.dispatch_[wire::SshMessageType::KexInit], &handler1);
  EXPECT_NO_THROW(dispatcher.registerHandler(wire::SshMessageType::KexECDHInit, &handler1));
  EXPECT_EQ(2, dispatcher.dispatch_.size());
  EXPECT_EQ(dispatcher.dispatch_[wire::SshMessageType::KexECDHInit], &handler1);
  EXPECT_NO_THROW(dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1));
  EXPECT_EQ(3, dispatcher.dispatch_.size());
  EXPECT_EQ(dispatcher.dispatch_[wire::SshMessageType::Debug], &handler1);
}

TEST(SshMessageDispatcherTest, RegisterHandler_Duplicate) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageHandler> handler2;
  TestMessageDispatcher dispatcher;
  EXPECT_NO_THROW(dispatcher.registerHandler(wire::SshMessageType::KexInit, &handler1));
  EXPECT_THROW_WITH_MESSAGE(dispatcher.registerHandler(wire::SshMessageType::KexInit, &handler2),
                            EnvoyException,
                            "duplicate registration of message type: KexInit (20)");
  EXPECT_EQ(1, dispatcher.dispatch_.size());
  EXPECT_EQ(dispatcher.dispatch_[wire::SshMessageType::KexInit], &handler1);
}

TEST(SshMessageDispatcherTest, UnregisterHandlerById) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageHandler> handler2;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::KexInit, &handler1);
  dispatcher.registerHandler(wire::SshMessageType::KexECDHInit, &handler2);
  EXPECT_EQ(2, dispatcher.dispatch_.size());
  dispatcher.unregisterHandler(wire::SshMessageType::Debug); // no-op
  EXPECT_EQ(2, dispatcher.dispatch_.size());
  dispatcher.unregisterHandler(wire::SshMessageType::KexInit);
  EXPECT_EQ(1, dispatcher.dispatch_.size());
  EXPECT_EQ(dispatcher.dispatch_[wire::SshMessageType::KexECDHInit], &handler2);
  dispatcher.unregisterHandler(wire::SshMessageType::KexECDHInit);
  EXPECT_EQ(0, dispatcher.dispatch_.size());
  dispatcher.unregisterHandler(wire::SshMessageType::KexECDHInit); // no-op
  EXPECT_EQ(0, dispatcher.dispatch_.size());
}

TEST(SshMessageDispatcherTest, UnregisterHandlerByHandlerPtr) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageHandler> handler2;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::KexInit, &handler1);
  dispatcher.registerHandler(wire::SshMessageType::KexECDHInit, &handler1);
  dispatcher.registerHandler(wire::SshMessageType::KexECDHReply, &handler2);
  EXPECT_EQ(3, dispatcher.dispatch_.size());
  dispatcher.unregisterHandler(nullptr); // no-op
  EXPECT_EQ(3, dispatcher.dispatch_.size());
  dispatcher.unregisterHandler(&handler1);
  EXPECT_EQ(1, dispatcher.dispatch_.size());
  EXPECT_EQ(dispatcher.dispatch_[wire::SshMessageType::KexECDHReply], &handler2);
  dispatcher.unregisterHandler(&handler2);
  EXPECT_EQ(0, dispatcher.dispatch_.size());
  dispatcher.unregisterHandler(&handler2); // no-op
  EXPECT_EQ(0, dispatcher.dispatch_.size());
}

TEST(SshMessageDispatcherTest, InstallMiddleware) {
  TestMessageDispatcher dispatcher;
  EXPECT_TRUE(dispatcher.middlewares_.empty());
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  dispatcher.installMiddleware(&middleware1);
  EXPECT_EQ(std::list<MessageMiddleware<wire::Message>*>{&middleware1}, dispatcher.middlewares_);
}

TEST(SshMessageDispatcherTest, Dispatch) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageHandler> handler2;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.registerHandler(wire::SshMessageType::Ignore, &handler2);
  IN_SEQUENCE;
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg, _)))
    .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(handler2, handleMessage(MSG(wire::IgnoreMsg, _)))
    .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(dispatcher.dispatch(wire::DebugMsg{}));
  EXPECT_OK(dispatcher.dispatch(wire::IgnoreMsg{}));
}

TEST(SshMessageDispatcherTest, Dispatch_Error) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg, _)))
    .WillOnce(Return(absl::InvalidArgumentError("error!")));

  EXPECT_EQ(absl::InvalidArgumentError("error!"), dispatcher.dispatch(wire::DebugMsg{}));
}

TEST(SshMessageDispatcherTest, Dispatch_NoMatchingHandler) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  TestMessageDispatcher dispatcher;
  EXPECT_EQ(absl::InvalidArgumentError("unexpected message received: KexInit (20)"),
            dispatcher.dispatch(wire::KexInitMsg{}));
  dispatcher.registerHandler(wire::SshMessageType::Ignore, &handler1);
  EXPECT_EQ(absl::InvalidArgumentError("unexpected message received: Debug (4)"),
            dispatcher.dispatch(wire::DebugMsg{}));
  dispatcher.unregisterHandler(wire::SshMessageType::Ignore);
  EXPECT_EQ(absl::InvalidArgumentError("unexpected message received: Ignore (2)"),
            dispatcher.dispatch(wire::IgnoreMsg{}));
}

TEST(SshMessageDispatcherTest, Middleware_Continue) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.installMiddleware(&middleware1);

  IN_SEQUENCE;
  EXPECT_CALL(middleware1, interceptMessage(MSG(wire::DebugMsg,
                                                FIELD_EQ(message, "foo"))))
    .WillOnce(Return(Continue));
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg,
                                          FIELD_EQ(message, "foo"))))
    .WillOnce(Return(absl::OkStatus()));
  wire::DebugMsg msg;
  msg.message = "foo";
  EXPECT_OK(dispatcher.dispatch(std::move(msg)));
}

TEST(SshMessageDispatcherTest, Middleware_ContinueWithMutation) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.installMiddleware(&middleware1);

  IN_SEQUENCE;
  EXPECT_CALL(middleware1, interceptMessage(MSG(wire::DebugMsg,
                                                FIELD_EQ(message, "foo"))))
    .WillOnce(Invoke([](wire::Message& m) {
      m.visit([](wire::DebugMsg& msg) { *msg.message += " bar"; },
              [](auto&) { FAIL() << "wrong message type"; });
      return Continue;
    }));
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg,
                                          FIELD_EQ(message, "foo bar"))))
    .WillOnce(Return(absl::OkStatus()));

  wire::DebugMsg msg;
  msg.message = "foo";
  EXPECT_OK(dispatcher.dispatch(std::move(msg)));
}

TEST(SshMessageDispatcherTest, Middleware_Break) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.installMiddleware(&middleware1);

  EXPECT_CALL(middleware1, interceptMessage(MSG(wire::DebugMsg,
                                                FIELD_EQ(message, "foo"))))
    .WillOnce(Return(Break));

  wire::DebugMsg msg;
  msg.message = "foo";
  EXPECT_OK(dispatcher.dispatch(std::move(msg)));
}

TEST(SshMessageDispatcherTest, Middleware_Error) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.installMiddleware(&middleware1);

  EXPECT_CALL(middleware1, interceptMessage(MSG(wire::DebugMsg,
                                                FIELD_EQ(message, "foo"))))
    .WillOnce(Return(absl::InvalidArgumentError("error!")));

  wire::DebugMsg msg;
  msg.message = "foo";
  EXPECT_EQ(absl::InvalidArgumentError("error!"), dispatcher.dispatch(std::move(msg)));
}

TEST(SshMessageDispatcherTest, Middleware_ContinueAndUninstallSelf) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.installMiddleware(&middleware1);

  IN_SEQUENCE;
  EXPECT_CALL(middleware1, interceptMessage(MSG(wire::DebugMsg,
                                                FIELD_EQ(message, "foo"))))
    .WillOnce(Invoke([](wire::Message& m) {
      m.visit([](wire::DebugMsg& msg) { *msg.message += " bar"; },
              [](auto&) { FAIL() << "wrong message type"; });
      return Continue | UninstallSelf;
    }))
    .RetiresOnSaturation();
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg,
                                          FIELD_EQ(message, "foo bar"))))
    .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg,
                                          FIELD_EQ(message, "foo"))))
    .WillOnce(Return(absl::OkStatus()));

  wire::DebugMsg msg;
  msg.message = "foo";
  EXPECT_OK(dispatcher.dispatch(auto(msg)));
  EXPECT_OK(dispatcher.dispatch(auto(msg)));
}

TEST(SshMessageDispatcherTest, Middleware_BreakAndUninstallSelf) {
  testing::StrictMock<MockSshMessageHandler> handler1;
  testing::StrictMock<MockSshMessageMiddleware> middleware1;
  TestMessageDispatcher dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::Debug, &handler1);
  dispatcher.installMiddleware(&middleware1);

  IN_SEQUENCE;
  EXPECT_CALL(middleware1, interceptMessage(MSG(wire::DebugMsg,
                                                FIELD_EQ(message, "foo"))))
    .WillOnce(Invoke([](wire::Message& m) {
      m.visit([](wire::DebugMsg& msg) { *msg.message += " bar"; },
              [](auto&) { FAIL() << "wrong message type"; });
      return Break | UninstallSelf;
    }))
    .RetiresOnSaturation();
  EXPECT_CALL(handler1, handleMessage(MSG(wire::DebugMsg,
                                          FIELD_EQ(message, "foo"))))
    .WillOnce(Return(absl::OkStatus()));

  wire::DebugMsg msg;
  msg.message = "foo";
  EXPECT_OK(dispatcher.dispatch(auto(msg)));
  EXPECT_TRUE(dispatcher.middlewares_.empty());
  EXPECT_OK(dispatcher.dispatch(auto(msg)));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec