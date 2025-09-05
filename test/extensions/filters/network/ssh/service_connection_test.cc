#include "gtest/gtest.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/grpc/mocks.h"
#include "test/test_common/utility.h"

#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

template <typename T>
T populatedMessage() {
  T msg;
  wire::test::populateFields(msg);
  return msg;
}

class TestSshMessageDispatcher : public SshMessageDispatcher {
public:
  using SshMessageDispatcher::dispatch;
  using SshMessageDispatcher::dispatch_;
};

class TestStreamMgmtServerMessageDispatcher : public StreamMgmtServerMessageDispatcher {
public:
  using StreamMgmtServerMessageDispatcher::dispatch_;
};

class DownstreamConnectionServiceTest : public testing::Test {
public:
  DownstreamConnectionServiceTest() {
    transport_ = std::make_unique<testing::StrictMock<MockDownstreamTransportCallbacks>>();
    server_factory_context_ = std::make_unique<testing::NiceMock<Server::Configuration::MockServerFactoryContext>>();
    service_ = std::make_unique<DownstreamConnectionService>(
      *transport_,
      server_factory_context_->api(),
      StreamTracker::fromContext(*server_factory_context_, StreamTrackerConfig{}));

    service_->registerMessageHandlers(msg_dispatcher_);
    EXPECT_CALL(*transport_, authInfo())
      .WillRepeatedly(ReturnRef(transport_auth_info_));
  }

  void StartHijackedChannel() { // NOLINT
    hijacked_client_ = std::make_shared<testing::StrictMock<Grpc::MockAsyncClient>>();
    EXPECT_CALL(*hijacked_client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
      .WillOnce(Return(&channel_stream_));
    transport_auth_info_.channel_mode = ChannelMode::Hijacked;
    transport_auth_info_.allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
    transport_auth_info_.allow_response->mutable_internal();
    service_->enableChannelHijack(mock_hijack_callbacks_, {}, hijacked_client_);
    EXPECT_OK(msg_dispatcher_.dispatch(wire::ChannelOpenMsg{
      .channel_type = "session"s,
      .sender_channel = 123,
    }));
    typed_channel_stream_ = &channel_stream_;
    testing::Mock::VerifyAndClearExpectations(hijacked_client_.get());
  };

protected:
  AuthInfo transport_auth_info_;
  TestSshMessageDispatcher msg_dispatcher_;
  std::unique_ptr<testing::StrictMock<MockDownstreamTransportCallbacks>> transport_;
  std::unique_ptr<testing::NiceMock<Server::Configuration::MockServerFactoryContext>> server_factory_context_;
  std::unique_ptr<DownstreamConnectionService> service_;
  std::shared_ptr<testing::StrictMock<Grpc::MockAsyncClient>> hijacked_client_;
  testing::StrictMock<Grpc::MockAsyncStream> channel_stream_;
  Grpc::AsyncStream<ChannelMessage> typed_channel_stream_;
  testing::StrictMock<MockHijackedChannelCallbacks> mock_hijack_callbacks_;
};

TEST_F(DownstreamConnectionServiceTest, Name) {
  ASSERT_EQ("ssh-connection", service_->name());
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageHijacked) {
  wire::Message msg{};
  msg.message = populatedMessage<wire::ChannelDataMsg>();

  // If there is a hijacked channel, dispatched messages should be sent there instead.
  StartHijackedChannel();
  // Verify that the proto version of the message matches the original message.
  Buffer::InstancePtr request;
  EXPECT_CALL(channel_stream_, sendMessageRaw_(_, false))
    .WillOnce([&](Buffer::InstancePtr& arg, [[maybe_unused]] bool end_stream) {
      request = std::move(arg);
    });

  ASSERT_OK(msg_dispatcher_.dispatch(auto(msg)));

  pomerium::extensions::ssh::ChannelMessage proto_msg;
  proto_msg.ParseFromArray(request->linearize(request->length()), static_cast<int>(request->length()));
  Buffer::OwnedImpl buf;
  buf.add(proto_msg.raw_bytes().value());
  wire::Message decoded_msg;
  ASSERT_OK(decoded_msg.decode(buf, buf.length()).status());
  ASSERT_EQ(msg, decoded_msg);
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageHijackedInvalid) {
  wire::ChannelDataMsg msg{};
  std::string data_too_long(wire::MaxPacketSize, 'A');
  msg.data = to_bytes(data_too_long);

  transport_auth_info_.channel_mode = ChannelMode::Hijacked;

  auto r = msg_dispatcher_.dispatch(wire::Message{msg});
  ASSERT_EQ(absl::InvalidArgumentError("received invalid message: ABORTED: message size too large"), r);
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageHijackedNoStream) {
  auto msg = populatedMessage<wire::ChannelDataMsg>();

  transport_auth_info_.channel_mode = ChannelMode::Hijacked;

  auto r = msg_dispatcher_.dispatch(wire::Message{msg});
  ASSERT_EQ(absl::CancelledError("connection closed"), r);
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageUnknown) {
  auto r = msg_dispatcher_.dispatch(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("unknown message"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytes) {
  StartHijackedChannel();

  wire::Message expected_msg{};
  expected_msg = wire::ChannelDataMsg{
    .recipient_channel = 123,
    .data = "EXAMPLE-DATA"_bytes,
  };
  auto b = wire::encodeTo<std::string>(expected_msg);
  ASSERT_OK(b.status());
  ProtobufWkt::BytesValue bytes_value;
  bytes_value.set_value(*b);
  pomerium::extensions::ssh::ChannelMessage channel_msg;
  *channel_msg.mutable_raw_bytes() = bytes_value;

  EXPECT_CALL(*transport_, sendMessageToConnection(Eq(expected_msg)))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  typed_channel_stream_.sendMessage(std::move(channel_msg), false);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytesEmpty) {
  StartHijackedChannel();

  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_raw_bytes();

  EXPECT_CALL(*transport_, sendMessageToConnection(wire::Message{}))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  typed_channel_stream_->sendMessage(std::move(channel_msg), false);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytesInvalid) {
  StartHijackedChannel();

  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_raw_bytes()->set_value("\x14");

  EXPECT_CALL(*transport_, terminate(absl::InvalidArgumentError("received invalid channel message: short read")));

  typed_channel_stream_->sendMessage(std::move(channel_msg), false);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffUpstream) {
  StartHijackedChannel();

  auto hijacked_stream = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>();
  transport_auth_info_.server_version = "example-server-version"s,
  transport_auth_info_.stream_id = 42;
  transport_auth_info_.channel_mode = ChannelMode::Hijacked;

  pomerium::extensions::ssh::SSHChannelControlAction action{};
  auto* handoff = action.mutable_hand_off();
  auto* upstream_auth = handoff->mutable_upstream_auth();
  upstream_auth->mutable_upstream()->set_hostname("example-hostname");
  auto* channel_info = handoff->mutable_downstream_channel_info();
  channel_info->set_channel_type("channel-type");
  channel_info->set_downstream_channel_id(1);
  auto* pty_info = handoff->mutable_downstream_pty_info();
  pty_info->set_width_columns(80);
  pty_info->set_height_rows(24);
  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

  AuthInfoSharedPtr new_auth_info;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&new_auth_info));

  typed_channel_stream_->sendMessage(std::move(channel_msg), false);

  ASSERT_EQ("example-server-version", new_auth_info->server_version);
  ASSERT_EQ(42, new_auth_info->stream_id);
  ASSERT_EQ(ChannelMode::Handoff, new_auth_info->channel_mode);
  ASSERT_TRUE(new_auth_info->handoff_info.handoff_in_progress);
  ASSERT_THAT(*new_auth_info->handoff_info.channel_info, Envoy::ProtoEq(*channel_info));
  ASSERT_THAT(*new_auth_info->handoff_info.pty_info, Envoy::ProtoEq(*pty_info));
  ASSERT_THAT(*new_auth_info->allow_response, Envoy::ProtoEq(*upstream_auth));
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffUpstreamNoInfo) {
  StartHijackedChannel();

  auto hijacked_stream = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>();
  transport_auth_info_.server_version = "example-server-version"s,
  transport_auth_info_.stream_id = 42;
  transport_auth_info_.channel_mode = ChannelMode::Hijacked;

  pomerium::extensions::ssh::SSHChannelControlAction action{};
  auto* upstream_auth = action.mutable_hand_off()->mutable_upstream_auth();
  upstream_auth->mutable_upstream();
  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

  AuthInfoSharedPtr new_auth_info;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&new_auth_info));

  typed_channel_stream_->sendMessage(std::move(channel_msg), false);

  ASSERT_EQ("example-server-version", new_auth_info->server_version);
  ASSERT_EQ(42, new_auth_info->stream_id);
  ASSERT_EQ(ChannelMode::Handoff, new_auth_info->channel_mode);
  ASSERT_TRUE(new_auth_info->handoff_info.handoff_in_progress);
  ASSERT_EQ(nullptr, new_auth_info->handoff_info.channel_info);
  ASSERT_EQ(nullptr, new_auth_info->handoff_info.pty_info);
  ASSERT_THAT(*new_auth_info->allow_response, Envoy::ProtoEq(*upstream_auth));
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffMirror) {
  StartHijackedChannel();

  // "MirrorSessionTarget" is not supported yet.
  pomerium::extensions::ssh::SSHChannelControlAction action{};
  action.mutable_hand_off()->mutable_upstream_auth()->mutable_mirror_session();
  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

  EXPECT_CALL(*transport_, terminate(absl::UnavailableError("session mirroring feature not available")));
  typed_channel_stream_->sendMessage(std::move(channel_msg), false);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffInternal) {
  StartHijackedChannel();

  // "InternalTarget" is not a valid target for a handoff.
  pomerium::extensions::ssh::SSHChannelControlAction action{};
  action.mutable_hand_off()->mutable_upstream_auth()->mutable_internal();
  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

  EXPECT_CALL(*transport_, terminate(absl::InternalError("received invalid channel message: unexpected target: 3")));
  typed_channel_stream_->sendMessage(std::move(channel_msg), false);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlUnknownAction) {
  StartHijackedChannel();

  pomerium::extensions::ssh::ChannelMessage channel_msg;
  channel_msg.mutable_channel_control();

  EXPECT_CALL(*transport_, terminate(absl::InternalError("received invalid channel message: unknown action type: 0")));
  typed_channel_stream_->sendMessage(std::move(channel_msg), false);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageUnknown) {
  StartHijackedChannel();

  pomerium::extensions::ssh::ChannelMessage channel_msg;

  EXPECT_CALL(*transport_, terminate(absl::InternalError("received invalid channel message: unknown message type: 0")));
  typed_channel_stream_->sendMessage(std::move(channel_msg), false);
}

class UpstreamConnectionServiceTest : public testing::Test {
public:
  UpstreamConnectionServiceTest() {
    transport_ = std::make_unique<testing::StrictMock<MockUpstreamTransportCallbacks>>();
    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<UpstreamConnectionService>(*transport_, *api_);
    service_->registerMessageHandlers(msg_dispatcher_);
  }

protected:
  TestSshMessageDispatcher msg_dispatcher_;
  std::unique_ptr<testing::StrictMock<MockUpstreamTransportCallbacks>> transport_;
  std::unique_ptr<testing::StrictMock<Api::MockApi>> api_;
  std::unique_ptr<UpstreamConnectionService> service_;
};

TEST_F(UpstreamConnectionServiceTest, RequestService) {
  wire::ServiceRequestMsg expectedRequest{.service_name = "ssh-connection"s};
  wire::Message msg{expectedRequest};
  EXPECT_CALL(*transport_, sendMessageToConnection(Eq(msg)))
    .WillOnce(Return(0));

  auto r = service_->requestService();
  EXPECT_OK(r);
}

TEST_F(UpstreamConnectionServiceTest, onServiceAccepted) {
  ASSERT_OK(service_->onServiceAccepted());
}

TEST_F(UpstreamConnectionServiceTest, HandleMessageUnknown) {
  auto r = msg_dispatcher_.dispatch(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("unknown message"), r);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec