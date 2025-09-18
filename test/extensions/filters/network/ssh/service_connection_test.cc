#include "gtest/gtest.h"
#include <algorithm>
#include <cstdlib>

#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/service_connection.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// NOLINTBEGIN(readability-identifier-naming)

template <typename Sink>
void AbslStringify(Sink& sink, const Peer& peer) {
  absl::Format(&sink, "%s", fmt::to_string(peer));
}

namespace test {

class ConnectionServiceTest : public testing::TestWithParam<Peer> {
public:
  ConnectionServiceTest()
      : service_(transport_, GetParam()) {
    EXPECT_CALL(transport_, channelIdManager)
      .WillRepeatedly(ReturnRef(channel_id_manager_));
    EXPECT_CALL(transport_, secretsProvider)
      .WillRepeatedly(ReturnRef(secrets_provider_));
  }

  Peer LocalPeer() const {
    return GetParam();
  }
  Peer RemotePeer() const {
    return GetParam() == Peer::Upstream ? Peer::Downstream : Peer::Upstream;
  }

  ChannelIDManager channel_id_manager_{100, 100};
  TestSecretsProvider secrets_provider_;
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
  ASSERT_OK(id);
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
  ASSERT_OK(id);
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
  ASSERT_OK(id);
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
  ASSERT_OK(id);
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
  ASSERT_OK(id);
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

TEST_P(ConnectionServiceTest, PassthroughNonChannelData) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks)
    .WillOnce([](ChannelCallbacks& cb) {
      EXPECT_THROW_WITH_MESSAGE(cb.sendMessageRemote(wire::IgnoreMsg{}).IgnoreError(),
                                Envoy::EnvoyException,
                                "bug: invalid message passed to sendMessageRemote()");
      return absl::OkStatus();
    });
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
}

TEST_P(ConnectionServiceTest, SendNonChannelDataInternal) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  auto& c1 = EXPECT_CALL(*ch1, setChannelCallbacks)
               .WillOnce([&](ChannelCallbacks& cb) {
                 EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::IgnoreMsg, _)))
                   .WillOnce(Return(0));
                 cb.sendMessageLocal(wire::IgnoreMsg{});
                 return absl::OkStatus();
               });
  EXPECT_CALL(*ch1, Die)
    .After(c1);
  auto id = service_.startChannel(std::move(ch1));
}

TEST_P(ConnectionServiceTest, SendNonChannelDataInternal_ErrorSendingMessageLocal) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  auto& c1 = EXPECT_CALL(*ch1, setChannelCallbacks)
               .WillOnce([&](ChannelCallbacks& cb) {
                 EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::IgnoreMsg, _)))
                   .WillOnce(Return(absl::InternalError("test error")));
                 EXPECT_CALL(transport_, terminate(absl::InternalError("test error")));
                 cb.sendMessageLocal(wire::IgnoreMsg{});
                 return absl::OkStatus();
               });
  EXPECT_CALL(*ch1, Die)
    .After(c1);
  auto id = service_.startChannel(std::move(ch1));
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

class TestSshMessageDispatcher : public SshMessageDispatcher {
public:
  using SshMessageDispatcher::dispatch;
  using SshMessageDispatcher::dispatch_;
};

class UpstreamConnectionServiceTest : public testing::Test {
public:
  UpstreamConnectionServiceTest() {
    transport_ = std::make_unique<testing::StrictMock<MockUpstreamTransportCallbacks>>();
    service_ = std::make_unique<UpstreamConnectionService>(*transport_);
    service_->registerMessageHandlers(msg_dispatcher_);
  }

protected:
  TestSshMessageDispatcher msg_dispatcher_;
  std::unique_ptr<testing::StrictMock<MockUpstreamTransportCallbacks>> transport_;
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
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("unknown message"), r);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec