#include "gtest/gtest.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/grpc/mocks.h"
#include "test/test_common/utility.h"

#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/mocks/api/mocks.h"
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
    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<DownstreamConnectionService>(*transport_, *api_);

    EXPECT_CALL(*transport_, authState())
      .WillRepeatedly(ReturnRef(transport_auth_state_));
  }

protected:
  AuthState transport_auth_state_;
  std::unique_ptr<testing::StrictMock<MockDownstreamTransportCallbacks>> transport_;
  std::unique_ptr<testing::StrictMock<Api::MockApi>> api_;
  std::unique_ptr<DownstreamConnectionService> service_;
};

TEST_F(DownstreamConnectionServiceTest, Name) {
  ASSERT_EQ("ssh-connection", service_->name());
}

TEST_F(DownstreamConnectionServiceTest, HandleMessage) {
  // Verify that all known message types will be forwarded when dispatched.
  std::vector<wire::Message> messages{
    populatedMessage<wire::ChannelOpenMsg>(),
    populatedMessage<wire::ChannelWindowAdjustMsg>(),
    populatedMessage<wire::ChannelDataMsg>(),
    populatedMessage<wire::ChannelExtendedDataMsg>(),
    populatedMessage<wire::ChannelEOFMsg>(),
    populatedMessage<wire::ChannelCloseMsg>(),
    populatedMessage<wire::ChannelRequestMsg>(),
    populatedMessage<wire::ChannelSuccessMsg>(),
    populatedMessage<wire::ChannelFailureMsg>(),
  };

  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  EXPECT_EQ(messages.size(), d.dispatch_.size());
  for (auto msg : messages) {
    EXPECT_CALL(*transport_, forward(Eq(msg), FrameTags{}));
    ASSERT_OK(d.dispatch(auto(msg)));
  }
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageHijacked) {
  wire::Message msg{};
  msg.message = populatedMessage<wire::ChannelDataMsg>();

  // If there is a hijacked channel, dispatched messages should be sent there instead.
  testing::StrictMock<Grpc::MockAsyncStream> stream;
  auto stream_ptr = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>(&stream);
  transport_auth_state_.hijacked_stream = stream_ptr;
  transport_auth_state_.channel_mode = ChannelMode::Hijacked;

  // Verify that the proto version of the message matches the original message.
  Buffer::InstancePtr request;
  EXPECT_CALL(stream, sendMessageRaw_(_, false))
    .WillOnce([&](Buffer::InstancePtr& arg, [[maybe_unused]] bool end_stream) {
      request = std::move(arg);
    });

  ASSERT_OK(service_->handleMessage(auto(msg)));

  pomerium::extensions::ssh::ChannelMessage proto_msg;
  proto_msg.ParseFromArray(request->linearize(request->length()), request->length());
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

  transport_auth_state_.channel_mode = ChannelMode::Hijacked;

  auto r = service_->handleMessage(wire::Message{msg});
  ASSERT_EQ(absl::InvalidArgumentError("received invalid message: ABORTED: message size too large"), r);
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageHijackedNoStream) {
  auto msg = populatedMessage<wire::ChannelDataMsg>();

  transport_auth_state_.channel_mode = ChannelMode::Hijacked;

  auto r = service_->handleMessage(wire::Message{msg});
  ASSERT_EQ(absl::CancelledError("connection closed"), r);
}

TEST_F(DownstreamConnectionServiceTest, HandleMessageUnknown) {
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("unknown message"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytes) {
  wire::Message expected_msg{};
  expected_msg = wire::ChannelDataMsg{
    .recipient_channel = 123,
    .data = "EXAMPLE-DATA"_bytes,
  };
  auto b = wire::encodeTo<std::string>(expected_msg);
  ASSERT_OK(b.status());
  ProtobufWkt::BytesValue bytes_value;
  bytes_value.set_value(*b);
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  *channel_msg->mutable_raw_bytes() = bytes_value;

  EXPECT_CALL(*transport_, sendMessageToConnection(Eq(expected_msg)))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::UnknownError("sentinel"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytesEmpty) {
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_raw_bytes();

  EXPECT_CALL(*transport_, sendMessageToConnection(wire::Message{}))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::UnknownError("sentinel"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytesInvalid) {
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_raw_bytes()->set_value("\x14");

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::InvalidArgumentError("received invalid channel message: short read"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffUpstream) {
  auto hijacked_stream = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>();
  transport_auth_state_.server_version = "example-server-version"s,
  transport_auth_state_.stream_id = 42;
  transport_auth_state_.hijacked_stream = hijacked_stream;
  transport_auth_state_.channel_mode = ChannelMode::Hijacked;

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
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_channel_control()->mutable_control_action()->PackFrom(action);

  AuthStateSharedPtr new_auth_state;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&new_auth_state));

  ASSERT_OK(service_->onReceiveMessage(std::move(channel_msg)));

  ASSERT_EQ("example-server-version", new_auth_state->server_version);
  ASSERT_EQ(42, new_auth_state->stream_id);
  ASSERT_EQ(hijacked_stream, new_auth_state->hijacked_stream.lock());
  ASSERT_EQ(ChannelMode::Handoff, new_auth_state->channel_mode);
  ASSERT_TRUE(new_auth_state->handoff_info.handoff_in_progress);
  ASSERT_THAT(*new_auth_state->handoff_info.channel_info, Envoy::ProtoEq(*channel_info));
  ASSERT_THAT(*new_auth_state->handoff_info.pty_info, Envoy::ProtoEq(*pty_info));
  ASSERT_THAT(*new_auth_state->allow_response, Envoy::ProtoEq(*upstream_auth));
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffUpstreamNoInfo) {
  auto hijacked_stream = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>();
  transport_auth_state_.server_version = "example-server-version"s,
  transport_auth_state_.stream_id = 42;
  transport_auth_state_.hijacked_stream = hijacked_stream;
  transport_auth_state_.channel_mode = ChannelMode::Hijacked;

  pomerium::extensions::ssh::SSHChannelControlAction action{};
  auto* upstream_auth = action.mutable_hand_off()->mutable_upstream_auth();
  upstream_auth->mutable_upstream();
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_channel_control()->mutable_control_action()->PackFrom(action);

  AuthStateSharedPtr new_auth_state;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&new_auth_state));

  ASSERT_OK(service_->onReceiveMessage(std::move(channel_msg)));

  ASSERT_EQ("example-server-version", new_auth_state->server_version);
  ASSERT_EQ(42, new_auth_state->stream_id);
  ASSERT_EQ(hijacked_stream, new_auth_state->hijacked_stream.lock());
  ASSERT_EQ(ChannelMode::Handoff, new_auth_state->channel_mode);
  ASSERT_TRUE(new_auth_state->handoff_info.handoff_in_progress);
  ASSERT_EQ(nullptr, new_auth_state->handoff_info.channel_info);
  ASSERT_EQ(nullptr, new_auth_state->handoff_info.pty_info);
  ASSERT_THAT(*new_auth_state->allow_response, Envoy::ProtoEq(*upstream_auth));
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffMirror) {
  // "MirrorSessionTarget" is not supported yet.
  pomerium::extensions::ssh::SSHChannelControlAction action{};
  action.mutable_hand_off()->mutable_upstream_auth()->mutable_mirror_session();
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_channel_control()->mutable_control_action()->PackFrom(action);

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::UnavailableError("session mirroring feature not available"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffInternal) {
  // "InternalTarget" is not a valid target for a handoff.
  pomerium::extensions::ssh::SSHChannelControlAction action{};
  action.mutable_hand_off()->mutable_upstream_auth()->mutable_internal();
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_channel_control()->mutable_control_action()->PackFrom(action);

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::InternalError("received invalid channel message: unexpected target: 3"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlDisconnect) {
  pomerium::extensions::ssh::SSHChannelControlAction action{};
  auto* disconnect = action.mutable_disconnect();
  disconnect->set_reason_code(999);
  disconnect->set_description("disconnect description");
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_channel_control()->mutable_control_action()->PackFrom(action);

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::CancelledError("disconnect description"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlUnknownAction) {
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();
  channel_msg->mutable_channel_control();

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::InternalError("received invalid channel message: unknown action type: 0"), r);
}

TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageUnknown) {
  auto channel_msg = std::make_unique<pomerium::extensions::ssh::ChannelMessage>();

  auto r = service_->onReceiveMessage(std::move(channel_msg));
  ASSERT_EQ(absl::InternalError("received invalid channel message: unknown message type: 0"), r);
}

TEST_F(DownstreamConnectionServiceTest, StreamCallbacks) {
  Envoy::Event::MockDispatcher dispatcher;
  ASSERT_OK(service_->onStreamBegin(AuthState{}, dispatcher));
  service_->onStreamEnd();
}

class UpstreamConnectionServiceTest : public testing::Test {
public:
  UpstreamConnectionServiceTest() {
    transport_ = std::make_unique<testing::StrictMock<MockUpstreamTransportCallbacks>>();
    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<UpstreamConnectionService>(*transport_, *api_);
  }

protected:
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

TEST_F(UpstreamConnectionServiceTest, HandleMessage) {
  // Verify that all known message types will be forwarded when dispatched.
  std::vector<wire::Message> messages{
    populatedMessage<wire::ChannelOpenConfirmationMsg>(),
    populatedMessage<wire::ChannelOpenFailureMsg>(),
    populatedMessage<wire::ChannelWindowAdjustMsg>(),
    populatedMessage<wire::ChannelDataMsg>(),
    populatedMessage<wire::ChannelExtendedDataMsg>(),
    populatedMessage<wire::ChannelEOFMsg>(),
    populatedMessage<wire::ChannelCloseMsg>(),
    populatedMessage<wire::ChannelRequestMsg>(),
    populatedMessage<wire::ChannelSuccessMsg>(),
    populatedMessage<wire::ChannelFailureMsg>(),
  };

  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  EXPECT_EQ(messages.size(), d.dispatch_.size());
  for (auto msg : messages) {
    EXPECT_CALL(*transport_, forward(Eq(msg), FrameTags{}));
    ASSERT_OK(d.dispatch(auto(msg)));
  }
}

TEST_F(UpstreamConnectionServiceTest, HandleMessageUnknown) {
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("unknown message"), r);
}

TEST_F(UpstreamConnectionServiceTest, StreamCallbacks) {
  Envoy::Event::MockDispatcher dispatcher;
  ASSERT_OK(service_->onStreamBegin(AuthState{}, dispatcher));
  service_->onStreamEnd();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec