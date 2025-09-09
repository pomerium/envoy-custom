#include "gtest/gtest.h"
#include <algorithm>
#include <cstdlib>
// #include "test/mocks/event/mocks.h"
// #include "test/mocks/grpc/mocks.h"
// #include "test/test_common/utility.h"

#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
// #include "source/extensions/filters/network/ssh/wire/encoding.h"
// #include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
// #include "test/mocks/server/server_factory_context.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// NOLINTBEGIN(readability-identifier-naming)

template <typename Sink>
void AbslStringify(Sink& sink, const Peer& peer) {
  absl::Format(sink, fmt::to_string(peer));
}

namespace test {

class ConnectionServiceTest : public testing::TestWithParam<Peer> {
public:
  ConnectionServiceTest()
      : service_(transport_, GetParam()) {
    EXPECT_CALL(transport_, channelIdManager)
      .WillRepeatedly(ReturnRef(channel_id_manager_));
  }

  Peer LocalPeer() const {
    return GetParam();
  }
  Peer RemotePeer() const {
    return GetParam() == Peer::Upstream ? Peer::Downstream : Peer::Upstream;
  }

  ChannelIDManager channel_id_manager_{100, 100};
  testing::StrictMock<MockTransportCallbacks> transport_;
  ConnectionService service_;
};

// NOLINTEND(readability-identifier-naming)

TEST_P(ConnectionServiceTest, Name) {
  ASSERT_EQ("ssh-connection", service_.name());
}

TEST_P(ConnectionServiceTest, StartChannel_NewID) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks);
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_OK(id.status());
  EXPECT_EQ(100, id.value());
}

TEST_P(ConnectionServiceTest, StartChannel_ExistingID) {
  auto _ = *channel_id_manager_.allocateNewChannel(GetParam());
  auto newId = *channel_id_manager_.allocateNewChannel(GetParam());
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks);
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1), newId);
  ASSERT_OK(id.status());
  EXPECT_EQ(101, id.value());
}

TEST_P(ConnectionServiceTest, StartChannel_ErrorAllocatingID) {
  for (int i = 0; i < 100; i++) {
    auto _ = *channel_id_manager_.allocateNewChannel(GetParam());
  }
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_EQ(absl::ResourceExhaustedError("failed to allocate ID"), id.status());
}

TEST_P(ConnectionServiceTest, StartChannel_ChannelCallbacksError) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks)
    .WillOnce([&](ChannelCallbacks&) {
      return absl::InternalError("test error");
    });
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_EQ(absl::InternalError("test error"), id.status());
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannelOnChannelOpen) {
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u), // the new internal ID
                                      FIELD_EQ(channel_type, "session"s)),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .channel_type = "session"s,
    .sender_channel = 1,
  }));

  auto owner = channel_id_manager_.owner(100);
  ASSERT_TRUE(owner.has_value());
  ASSERT_EQ(LocalPeer(), owner.value());
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannel_ErrorAllocatingID) {
  for (int i = 0; i < 100; i++) {
    auto _ = *channel_id_manager_.allocateNewChannel(GetParam());
  }
  ASSERT_EQ(
    absl::ResourceExhaustedError("error starting passthrough channel: failed to allocate ID"),
    service_.handleMessage(wire::ChannelOpenMsg{
      .channel_type = "session"s,
      .sender_channel = 1,
    }));
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannel_ChannelOpenConfirm) {
  auto internalId = *channel_id_manager_.allocateNewChannel(RemotePeer());
  // simulate a channel being created by the peer
  ASSERT_OK(channel_id_manager_.bindChannelID(internalId, PeerLocalID{
                                                            .channel_id = 1,
                                                            .local_peer = RemotePeer(),
                                                          }));

  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg,
                                      FIELD_EQ(recipient_channel, 1u), // remote peer's channel
                                      FIELD_EQ(sender_channel, internalId)),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = internalId,
    .sender_channel = 2, // local peer's channel
  }));

  auto owner = channel_id_manager_.owner(internalId);
  ASSERT_TRUE(owner.has_value());
  ASSERT_EQ(RemotePeer(), owner.value());
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannel_ChannelOpenConfirm_UnknownSenderChannel) {
  ASSERT_EQ(absl::InvalidArgumentError("received invalid ChannelOpenConfirmation message: unknown channel 100"),
            service_.handleMessage(wire::ChannelOpenConfirmationMsg{
              .recipient_channel = 100,
              .sender_channel = 2, // local peer's channel
            }));
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannel_ChannelOpenConfirm_InvalidSenderChannel) {
  auto internalId = *channel_id_manager_.allocateNewChannel(LocalPeer());
  auto expected = absl::InvalidArgumentError(fmt::format("expected channel {} to exist or be owned by the {} transport", internalId, RemotePeer()));
  ASSERT_EQ(expected,
            service_.handleMessage(wire::ChannelOpenConfirmationMsg{
              .recipient_channel = internalId,
              .sender_channel = 2, // local peer's channel
            }));
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannel_ChannelOpenConfirm_AlreadyKnown) {
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u),
                                      FIELD_EQ(channel_type, "session"s)),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .channel_type = "session"s,
    .sender_channel = 3,
  }));
  ASSERT_EQ(
    absl::InvalidArgumentError(fmt::format("received invalid ChannelOpenConfirmation message: channel 100 is already known to {}", LocalPeer())),
    service_.handleMessage(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = 100,
      .sender_channel = 3,
    }));
}

TEST_P(ConnectionServiceTest, OpenInternalChannel) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks);
  EXPECT_CALL(*ch1, onChannelOpened)
    .WillOnce([&](wire::ChannelOpenConfirmationMsg&& msg) {
      EXPECT_EQ(100, *msg.recipient_channel);
      EXPECT_EQ(100, *msg.sender_channel);
      return absl::OkStatus();
    });
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_OK(id.status());
  EXPECT_EQ(100, *id);
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = *id,
    .sender_channel = 1, // local peer's ID
  }));
}

TEST_P(ConnectionServiceTest, OpenInternalChannel_ErrorOnChannelOpened) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks);
  EXPECT_CALL(*ch1, onChannelOpened)
    .WillOnce([&](wire::ChannelOpenConfirmationMsg&&) {
      return absl::InternalError("test error");
    });
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_OK(id.status());
  EXPECT_EQ(100, *id);
  ASSERT_EQ(
    absl::InternalError("error opening channel: test error"),
    service_.handleMessage(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = *id,
      .sender_channel = 1, // local peer's IDq
    }));
}

TEST_P(ConnectionServiceTest, ChannelOpenFailure) {
  auto internalId = *channel_id_manager_.allocateNewChannel(RemotePeer());
  // simulate a channel being created by the peer
  ASSERT_OK(channel_id_manager_.bindChannelID(internalId, PeerLocalID{
                                                            .channel_id = 1,
                                                            .local_peer = RemotePeer(),
                                                          }));

  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenFailureMsg,
                                      FIELD_EQ(recipient_channel, 1u)), // remote peer's channel
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenFailureMsg{
    .recipient_channel = internalId,
  }));

  // the ID should be released locally
  ASSERT_TRUE(channel_id_manager_.owner(internalId).has_value());
  ASSERT_EQ(RemotePeer(), *channel_id_manager_.owner(internalId));
  // after the remote releases the channel, it should be freed
  channel_id_manager_.releaseChannelID(internalId, RemotePeer());

  ASSERT_FALSE(channel_id_manager_.owner(internalId).has_value());
}

TEST_P(ConnectionServiceTest, ChannelOpenFailure_UnknownChannel) {
  ASSERT_EQ(
    absl::InvalidArgumentError("received invalid ChannelOpenFailure message: unknown channel 100"),
    service_.handleMessage(
      wire::ChannelOpenFailureMsg{
        .recipient_channel = 100,
      }));
}

TEST_P(ConnectionServiceTest, ChannelOpenFailure_InvalidChannel) {
  auto internalId = *channel_id_manager_.allocateNewChannel(LocalPeer());
  auto expected = absl::InvalidArgumentError(fmt::format(
    "received invalid ChannelOpenFailure message: expected channel {} to exist or be owned by the {} transport",
    internalId, RemotePeer()));
  ASSERT_EQ(expected,
            service_.handleMessage(
              wire::ChannelOpenFailureMsg{
                .recipient_channel = internalId,
              }));
}

TEST_P(ConnectionServiceTest, CloseInternalChannel) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks);
  EXPECT_CALL(*ch1, onChannelOpened)
    .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelCloseMsg, _)))
    .WillOnce([&](wire::Message&&) {
      return absl::OkStatus();
    });
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_OK(id.status());
  EXPECT_EQ(100, *id);
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = *id,
    .sender_channel = 1, // local peer's ID
  }));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = *id,
  }));

  ASSERT_EQ(0, channel_id_manager_.numActiveChannels());
}

TEST_P(ConnectionServiceTest, CloseLocalPassthroughChannelWithNoRemoteRef) {
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u),
                                      FIELD_EQ(channel_type, "session"s)),
                                  _));

  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .channel_type = "session"s,
    .sender_channel = 1, // local peer's ID
  }));
  ASSERT_EQ(1, channel_id_manager_.numActiveChannels());
  ASSERT_EQ(
    absl::InvalidArgumentError(
      fmt::format("error processing outgoing message of type ChannelClose (97): internal channel 100 is not known to {} (state: Unbound)",
                  RemotePeer())),
    service_.handleMessage(wire::ChannelCloseMsg{
      .recipient_channel = 100,
    }));
  ASSERT_EQ(0, channel_id_manager_.numActiveChannels());
}

TEST_P(ConnectionServiceTest, CloseLocalPassthroughChannelWithRemoteRef) {
  IN_SEQUENCE;
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u),
                                      FIELD_EQ(channel_type, "session"s)),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .channel_type = "session"s,
    .sender_channel = 1, // local peer's ID
  }));
  ASSERT_EQ(1, channel_id_manager_.numActiveChannels());
  ASSERT_OK(channel_id_manager_.bindChannelID(100, PeerLocalID{
                                                     .channel_id = 2,
                                                     .local_peer = RemotePeer(),
                                                   }));
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg,
                                      FIELD_EQ(recipient_channel, 2u)),
                                  _));

  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = 100,
  }));
  // wait for the remote peer to release their ID
  ASSERT_EQ(1, channel_id_manager_.numActiveChannels());
  channel_id_manager_.releaseChannelID(100, RemotePeer());
  ASSERT_EQ(0, channel_id_manager_.numActiveChannels());
}

TEST_P(ConnectionServiceTest, CloseUnknownChannel) {
  ASSERT_EQ(
    absl::InvalidArgumentError("received message for unknown channel 100: ChannelClose (97)"),
    service_.handleMessage(wire::ChannelCloseMsg{
      .recipient_channel = 100,
    }));
}

TEST_P(ConnectionServiceTest, PassthroughChannelData) {
  std::vector<uint32_t> internalChannels;
  std::vector<Buffer::OwnedImpl> channelData;
  // set up 100 channels that will write their contents to the respective buffers in channelData
  for (int i = 0; i < 10; i++) {
    auto internalChannel = *channel_id_manager_.allocateNewChannel(RemotePeer());
    internalChannels.push_back(internalChannel);
    channelData.push_back(Buffer::OwnedImpl{});
    uint32_t upstreamId = 10u + i;
    ASSERT_OK(channel_id_manager_.bindChannelID(
      internalChannel, PeerLocalID{
                         .channel_id = upstreamId,
                         .local_peer = RemotePeer(),
                       }));

    EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg,
                                        FIELD_EQ(recipient_channel, upstreamId),
                                        FIELD_EQ(sender_channel, internalChannel)),
                                    _));
    EXPECT_CALL(transport_, forward(MSG(wire::ChannelDataMsg,
                                        FIELD_EQ(recipient_channel, upstreamId)),
                                    _))
      .WillRepeatedly(Invoke([i, &channelData](wire::Message&& msg, FrameTags) {
        msg.visit(
          [&](wire::ChannelDataMsg& msg) {
            channelData[i].add(msg.data->data(), msg.data->size());
          },
          [](auto&) {});
      }));
    ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = internalChannel,
      .sender_channel = 1u + i, // local peer's channel
    }));
  }

  // construct messages
  std::vector<wire::ChannelDataMsg> dataMsgs;
  dataMsgs.reserve(1000);
  std::vector<int> insertionOrder;
  insertionOrder.resize(1000);
  for (int i = 0; i < 1000; i++) {
    insertionOrder[i] = i % 10;
  }
  std::shuffle(insertionOrder.begin(), insertionOrder.end(), rng);

  std::vector<uint32_t> count;
  count.resize(10);
  for (int channelIdx : insertionOrder) {
    dataMsgs.push_back({
      .recipient_channel = internalChannels[channelIdx],
      .data = to_bytes(fmt::format("channel {}: packet {}\n", internalChannels[channelIdx], ++count[channelIdx])),
    });
  }

  // send messages
  for (auto&& msg : dataMsgs) {
    ASSERT_OK(service_.handleMessage(std::move(msg)));
  }

  // all buffers should contain the expected data
  for (int i = 0; i < 10; i++) {
    Buffer::OwnedImpl expected;
    for (int j = 0; j < 100; j++) {
      expected.add(fmt::format("channel {}: packet {}\n", internalChannels[i], j + 1));
    }
    EXPECT_EQ(expected.toString(), channelData[i].toString());
  }
}

TEST_P(ConnectionServiceTest, HandleMessageWithUnknownChannel) {
  auto internalChannel = *channel_id_manager_.allocateNewChannel(RemotePeer());
  uint32_t upstreamId = 10u;
  ASSERT_OK(channel_id_manager_.bindChannelID(
    internalChannel, PeerLocalID{
                       .channel_id = upstreamId,
                       .local_peer = RemotePeer(),
                     }));
  ASSERT_EQ(
    absl::InvalidArgumentError(fmt::format("received message for unknown channel {}: ChannelData (94)", internalChannel)),
    service_.handleMessage(wire::ChannelDataMsg{
      .recipient_channel = internalChannel,
    }));
  ASSERT_EQ(
    absl::InvalidArgumentError(fmt::format("received message for unknown channel {}: ChannelData (94)", internalChannel + 1)),
    service_.handleMessage(wire::ChannelDataMsg{
      .recipient_channel = internalChannel + 1,
    }));
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg, _), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = internalChannel,
    .sender_channel = 1u,
  }));
  ASSERT_EQ(
    absl::InvalidArgumentError(fmt::format("received message for unknown channel {}: ChannelData (94)", internalChannel + 1)),
    service_.handleMessage(wire::ChannelDataMsg{
      .recipient_channel = internalChannel + 1,
    }));
}

TEST_P(ConnectionServiceTest, UnknownMessage) {
  ASSERT_EQ(absl::InternalError("unknown message"),
            service_.handleMessage(wire::KexInitMsg{}));
}

INSTANTIATE_TEST_SUITE_P(ConnectionService, ConnectionServiceTest,
                         testing::Values(Peer::Downstream, Peer::Upstream));
// template <typename T>
// T populatedMessage() {
//   T msg;
//   wire::test::populateFields(msg);
//   return msg;
// }

// class TestSshMessageDispatcher : public SshMessageDispatcher {
// public:
//   using SshMessageDispatcher::dispatch;
//   using SshMessageDispatcher::dispatch_;
// };

// class TestStreamMgmtServerMessageDispatcher : public StreamMgmtServerMessageDispatcher {
// public:
//   using StreamMgmtServerMessageDispatcher::dispatch_;
// };

// class DownstreamConnectionServiceTest : public testing::TestWithParam<Peer> {
// public:
//   DownstreamConnectionServiceTest() {
//     transport_ = std::make_unique<testing::StrictMock<MockDownstreamTransportCallbacks>>();
//     server_factory_context_ = std::make_unique<testing::NiceMock<Server::Configuration::MockServerFactoryContext>>();
//     service_ = std::make_unique<DownstreamConnectionService>(
//       *transport_,
//       StreamTracker::fromContext(*server_factory_context_, StreamTrackerConfig{}));

//     service_->registerMessageHandlers(msg_dispatcher_);
//     EXPECT_CALL(*transport_, authInfo())
//       .WillRepeatedly(ReturnRef(transport_auth_info_));
//   }

//   void StartHijackedChannel() { // NOLINT
//     hijacked_client_ = std::make_shared<testing::StrictMock<Grpc::MockAsyncClient>>();
//     EXPECT_CALL(*hijacked_client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
//       .WillOnce(Return(&channel_stream_));
//     transport_auth_info_.channel_mode = ChannelMode::Hijacked;
//     transport_auth_info_.allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
//     transport_auth_info_.allow_response->mutable_internal();
//     service_->enableChannelHijack(mock_hijack_callbacks_, {}, hijacked_client_);
//     EXPECT_OK(msg_dispatcher_.dispatch(wire::ChannelOpenMsg{
//       .channel_type = "session"s,
//       .sender_channel = 123,
//     }));
//     typed_channel_stream_ = &channel_stream_;
//     testing::Mock::VerifyAndClearExpectations(hijacked_client_.get());
//   };

// protected:
//   AuthInfo transport_auth_info_;
//   TestSshMessageDispatcher msg_dispatcher_;
//   std::unique_ptr<testing::StrictMock<MockDownstreamTransportCallbacks>> transport_;
//   std::unique_ptr<testing::NiceMock<Server::Configuration::MockServerFactoryContext>> server_factory_context_;
//   std::unique_ptr<DownstreamConnectionService> service_;
//   std::shared_ptr<testing::StrictMock<Grpc::MockAsyncClient>> hijacked_client_;
//   testing::StrictMock<Grpc::MockAsyncStream> channel_stream_;
//   Grpc::AsyncStream<ChannelMessage> typed_channel_stream_;
//   testing::StrictMock<MockHijackedChannelCallbacks> mock_hijack_callbacks_;
// };

// TEST_F(DownstreamConnectionServiceTest, Name) {
//   ASSERT_EQ("ssh-connection", service_->name());
// }

// TEST_F(DownstreamConnectionServiceTest, HandleMessageHijacked) {
//   wire::Message msg{};
//   msg.message = populatedMessage<wire::ChannelDataMsg>();

//   // If there is a hijacked channel, dispatched messages should be sent there instead.
//   StartHijackedChannel();
//   // Verify that the proto version of the message matches the original message.
//   Buffer::InstancePtr request;
//   EXPECT_CALL(channel_stream_, sendMessageRaw_(_, false))
//     .WillOnce([&](Buffer::InstancePtr& arg, [[maybe_unused]] bool end_stream) {
//       request = std::move(arg);
//     });

//   ASSERT_OK(msg_dispatcher_.dispatch(auto(msg)));

//   pomerium::extensions::ssh::ChannelMessage proto_msg;
//   proto_msg.ParseFromArray(request->linearize(request->length()), static_cast<int>(request->length()));
//   Buffer::OwnedImpl buf;
//   buf.add(proto_msg.raw_bytes().value());
//   wire::Message decoded_msg;
//   ASSERT_OK(decoded_msg.decode(buf, buf.length()).status());
//   ASSERT_EQ(msg, decoded_msg);
// }

// TEST_F(DownstreamConnectionServiceTest, HandleMessageHijackedInvalid) {
//   wire::ChannelDataMsg msg{};
//   std::string data_too_long(wire::MaxPacketSize, 'A');
//   msg.data = to_bytes(data_too_long);

//   transport_auth_info_.channel_mode = ChannelMode::Hijacked;

//   auto r = msg_dispatcher_.dispatch(wire::Message{msg});
//   ASSERT_EQ(absl::InvalidArgumentError("received invalid message: ABORTED: message size too large"), r);
// }

// TEST_F(DownstreamConnectionServiceTest, HandleMessageHijackedNoStream) {
//   auto msg = populatedMessage<wire::ChannelDataMsg>();

//   transport_auth_info_.channel_mode = ChannelMode::Hijacked;

//   auto r = msg_dispatcher_.dispatch(wire::Message{msg});
//   ASSERT_EQ(absl::CancelledError("connection closed"), r);
// }

// TEST_F(DownstreamConnectionServiceTest, HandleMessageUnknown) {
//   auto r = msg_dispatcher_.dispatch(wire::Message{wire::DebugMsg{}});
//   ASSERT_EQ(absl::InternalError("unknown message"), r);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytes) {
//   StartHijackedChannel();

//   wire::Message expected_msg{};
//   expected_msg = wire::ChannelDataMsg{
//     .recipient_channel = 123,
//     .data = "EXAMPLE-DATA"_bytes,
//   };
//   auto b = wire::encodeTo<std::string>(expected_msg);
//   ASSERT_OK(b.status());
//   ProtobufWkt::BytesValue bytes_value;
//   bytes_value.set_value(*b);
//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   *channel_msg.mutable_raw_bytes() = bytes_value;

//   EXPECT_CALL(*transport_, sendMessageToConnection(Eq(expected_msg)))
//     .WillOnce(Return(absl::UnknownError("sentinel")));

//   typed_channel_stream_.sendMessage(std::move(channel_msg), false);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytesEmpty) {
//   StartHijackedChannel();

//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_raw_bytes();

//   EXPECT_CALL(*transport_, sendMessageToConnection(wire::Message{}))
//     .WillOnce(Return(absl::UnknownError("sentinel")));

//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageRawBytesInvalid) {
//   StartHijackedChannel();

//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_raw_bytes()->set_value("\x14");

//   EXPECT_CALL(*transport_, terminate(absl::InvalidArgumentError("received invalid channel message: short read")));

//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffUpstream) {
//   StartHijackedChannel();

//   auto hijacked_stream = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>();
//   transport_auth_info_.server_version = "example-server-version"s,
//   transport_auth_info_.stream_id = 42;
//   transport_auth_info_.channel_mode = ChannelMode::Hijacked;

//   pomerium::extensions::ssh::SSHChannelControlAction action{};
//   auto* handoff = action.mutable_hand_off();
//   auto* upstream_auth = handoff->mutable_upstream_auth();
//   upstream_auth->mutable_upstream()->set_hostname("example-hostname");
//   auto* channel_info = handoff->mutable_downstream_channel_info();
//   channel_info->set_channel_type("channel-type");
//   channel_info->set_downstream_channel_id(1);
//   auto* pty_info = handoff->mutable_downstream_pty_info();
//   pty_info->set_width_columns(80);
//   pty_info->set_height_rows(24);
//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

//   AuthInfoSharedPtr new_auth_info;
//   EXPECT_CALL(*transport_, initUpstream(_))
//     .WillOnce(SaveArg<0>(&new_auth_info));

//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);

//   ASSERT_EQ("example-server-version", new_auth_info->server_version);
//   ASSERT_EQ(42, new_auth_info->stream_id);
//   ASSERT_EQ(ChannelMode::Handoff, new_auth_info->channel_mode);
//   ASSERT_TRUE(new_auth_info->handoff_info.handoff_in_progress);
//   ASSERT_THAT(*new_auth_info->handoff_info.channel_info, Envoy::ProtoEq(*channel_info));
//   ASSERT_THAT(*new_auth_info->handoff_info.pty_info, Envoy::ProtoEq(*pty_info));
//   ASSERT_THAT(*new_auth_info->allow_response, Envoy::ProtoEq(*upstream_auth));
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffUpstreamNoInfo) {
//   StartHijackedChannel();

//   auto hijacked_stream = std::make_shared<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>>();
//   transport_auth_info_.server_version = "example-server-version"s,
//   transport_auth_info_.stream_id = 42;
//   transport_auth_info_.channel_mode = ChannelMode::Hijacked;

//   pomerium::extensions::ssh::SSHChannelControlAction action{};
//   auto* upstream_auth = action.mutable_hand_off()->mutable_upstream_auth();
//   upstream_auth->mutable_upstream();
//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

//   AuthInfoSharedPtr new_auth_info;
//   EXPECT_CALL(*transport_, initUpstream(_))
//     .WillOnce(SaveArg<0>(&new_auth_info));

//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);

//   ASSERT_EQ("example-server-version", new_auth_info->server_version);
//   ASSERT_EQ(42, new_auth_info->stream_id);
//   ASSERT_EQ(ChannelMode::Handoff, new_auth_info->channel_mode);
//   ASSERT_TRUE(new_auth_info->handoff_info.handoff_in_progress);
//   ASSERT_EQ(nullptr, new_auth_info->handoff_info.channel_info);
//   ASSERT_EQ(nullptr, new_auth_info->handoff_info.pty_info);
//   ASSERT_THAT(*new_auth_info->allow_response, Envoy::ProtoEq(*upstream_auth));
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffMirror) {
//   StartHijackedChannel();

//   // "MirrorSessionTarget" is not supported yet.
//   pomerium::extensions::ssh::SSHChannelControlAction action{};
//   action.mutable_hand_off()->mutable_upstream_auth()->mutable_mirror_session();
//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

//   EXPECT_CALL(*transport_, terminate(absl::UnavailableError("session mirroring feature not available")));
//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlHandoffInternal) {
//   StartHijackedChannel();

//   // "InternalTarget" is not a valid target for a handoff.
//   pomerium::extensions::ssh::SSHChannelControlAction action{};
//   action.mutable_hand_off()->mutable_upstream_auth()->mutable_internal();
//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_channel_control()->mutable_control_action()->PackFrom(action);

//   EXPECT_CALL(*transport_, terminate(absl::InternalError("received invalid channel message: unexpected target: 3")));
//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageChannelControlUnknownAction) {
//   StartHijackedChannel();

//   pomerium::extensions::ssh::ChannelMessage channel_msg;
//   channel_msg.mutable_channel_control();

//   EXPECT_CALL(*transport_, terminate(absl::InternalError("received invalid channel message: unknown action type: 0")));
//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);
// }

// TEST_F(DownstreamConnectionServiceTest, OnReceiveMessageUnknown) {
//   StartHijackedChannel();

//   pomerium::extensions::ssh::ChannelMessage channel_msg;

//   EXPECT_CALL(*transport_, terminate(absl::InternalError("received invalid channel message: unknown message type: 0")));
//   typed_channel_stream_->sendMessage(std::move(channel_msg), false);
// }

// class UpstreamConnectionServiceTest : public testing::Test {
// public:
//   UpstreamConnectionServiceTest() {
//     transport_ = std::make_unique<testing::StrictMock<MockUpstreamTransportCallbacks>>();
//     api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
//     service_ = std::make_unique<UpstreamConnectionService>(*transport_, *api_);
//     service_->registerMessageHandlers(msg_dispatcher_);
//   }

// protected:
//   TestSshMessageDispatcher msg_dispatcher_;
//   std::unique_ptr<testing::StrictMock<MockUpstreamTransportCallbacks>> transport_;
//   std::unique_ptr<testing::StrictMock<Api::MockApi>> api_;
//   std::unique_ptr<UpstreamConnectionService> service_;
// };

// TEST_F(UpstreamConnectionServiceTest, RequestService) {
//   wire::ServiceRequestMsg expectedRequest{.service_name = "ssh-connection"s};
//   wire::Message msg{expectedRequest};
//   EXPECT_CALL(*transport_, sendMessageToConnection(Eq(msg)))
//     .WillOnce(Return(0));

//   auto r = service_->requestService();
//   EXPECT_OK(r);
// }

// TEST_F(UpstreamConnectionServiceTest, onServiceAccepted) {
//   ASSERT_OK(service_->onServiceAccepted());
// }

// TEST_F(UpstreamConnectionServiceTest, HandleMessageUnknown) {
//   auto r = msg_dispatcher_.dispatch(wire::Message{wire::DebugMsg{}});
//   ASSERT_EQ(absl::InternalError("unknown message"), r);
// }

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec