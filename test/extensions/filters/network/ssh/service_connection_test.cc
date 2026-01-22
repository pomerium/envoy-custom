#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <cstdlib>

#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/mocks/event/mocks.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// NOLINTBEGIN(readability-identifier-naming)

template <typename Sink>
void AbslStringify(Sink& sink, const Peer& peer) {
  absl::Format(&sink, "%s", fmt::to_string(peer));
}

namespace test {

class TestConnectionService : public ConnectionService {
public:
  using ConnectionService::ConnectionService;

  using ConnectionService::preempt;

  ChannelCallbacksImpl& getChannelCallbacks(uint32_t id) {
    for (auto& cc : channel_callbacks_) {
      if (cc->channelId() == id) {
        return *cc;
      }
    }
    PANIC("test bug: channel id does not exist");
  }
};

class ConnectionServiceTest : public testing::TestWithParam<Peer> {
public:
  ConnectionServiceTest()
      : service_(transport_, GetParam()) {
    EXPECT_CALL(transport_, channelIdManager)
      .WillRepeatedly(ReturnRef(channel_id_manager_));
    EXPECT_CALL(transport_, secretsProvider)
      .WillRepeatedly(ReturnRef(secrets_provider_));
    EXPECT_CALL(transport_, statsScope)
      .Times(AnyNumber());
    EXPECT_CALL(transport_, connectionDispatcher)
      .WillRepeatedly([this] -> Envoy::OptRef<Envoy::Event::Dispatcher> {
        return mock_dispatcher_;
      });
  }

  Peer LocalPeer() const {
    return GetParam();
  }
  Peer RemotePeer() const {
    return GetParam() == Peer::Upstream ? Peer::Downstream : Peer::Upstream;
  }

  NiceMock<Envoy::Event::MockDispatcher> mock_dispatcher_; // field order is important
  ChannelIDManager channel_id_manager_{100, 100};
  TestSecretsProvider secrets_provider_;
  testing::StrictMock<MockTransportCallbacks> transport_;
  TestConnectionService service_;
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

TEST_P(ConnectionServiceTest, SetChannelCallbacks) {
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  IN_SEQUENCE;
  EXPECT_CALL(*ch1, setChannelCallbacks).WillOnce([](ChannelCallbacks& cb) {
    EXPECT_EQ(100, cb.channelId());
    EXPECT_NE(nullptr, &cb.scope());
    return absl::OkStatus();
  });
  EXPECT_CALL(*ch1, Die);
  auto id = service_.startChannel(std::move(ch1));
  ASSERT_OK(id);
  EXPECT_EQ(100, id.value());
}

TEST_P(ConnectionServiceTest, OpenPassthroughChannelOnChannelOpen) {
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u), // the new internal ID
                                      FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _))),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .sender_channel = 1,
    .request = wire::SessionChannelOpenMsg{},
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
      .sender_channel = 1,
      .request = wire::SessionChannelOpenMsg{},
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
                                      FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _))),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .sender_channel = 3,
    .request = wire::SessionChannelOpenMsg{},
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
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([&](wire::ChannelMessage&& msg) {
      auto confirm = msg.message.get<wire::ChannelOpenConfirmationMsg>();
      EXPECT_EQ(100, *confirm.recipient_channel);
      EXPECT_EQ(100, *confirm.sender_channel);
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
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce(Return(absl::InternalError("test error")));
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
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelCloseMsg, _)))
    .WillOnce(Return(absl::OkStatus()));
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

TEST_P(ConnectionServiceTest, InterruptInternalChannel) {
  EXPECT_CALL(transport_, streamId)
    .WillRepeatedly(Return(1));
  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  uint32_t id{};
  Envoy::Common::CallbackHandlePtr interruptCbHandle;
  {
    IN_SEQUENCE;
    EXPECT_CALL(*ch1, setChannelCallbacks)
      .WillOnce([&](ChannelCallbacks& cb) {
        interruptCbHandle = cb.addInterruptCallback([](absl::Status err, TransportCallbacks& transport_callbacks) {
          EXPECT_EQ(absl::InternalError("test error"), err);
          EXPECT_OK(transport_callbacks.sendMessageToConnection(wire::ChannelDataMsg{
            .recipient_channel = 1u, // note: manual channel id translation
            .data = "testing"_bytes,
          }));
        });
        return absl::OkStatus();
      });
    EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelOpenConfirmationMsg, _)))
      .WillOnce(Return(absl::OkStatus()));
    EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelCloseMsg, _)))
      .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(*ch1, Die);
    id = *service_.startChannel(std::move(ch1));
  }
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = id,
    .sender_channel = 1, // local peer's ID
  }));
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelDataMsg,
                                                      FIELD_EQ(recipient_channel, 1u),
                                                      FIELD_EQ(data, "testing"_bytes))))
    .WillOnce(Return(0));
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg,
                                                      FIELD_EQ(recipient_channel, 1u))))
    .WillOnce(InvokeWithoutArgs([&]() {
      EXPECT_OK(service_.handleMessage(wire::ChannelCloseMsg{
        .recipient_channel = id,
      }));
      return 0;
    }));

  ASSERT_TRUE(channel_id_manager_.isPreemptable(id, LocalPeer()));
  service_.preempt(service_.getChannelCallbacks(id), absl::InternalError("test error"));
}

TEST_P(ConnectionServiceTest, InterruptLocalPassthroughChannel) {
  EXPECT_CALL(transport_, streamId)
    .WillRepeatedly(Return(1));
  IN_SEQUENCE;
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u),
                                      FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _))),
                                  _));

  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .sender_channel = 1, // local peer's ID
    .request = wire::SessionChannelOpenMsg{},
  }));
  ASSERT_EQ(1, channel_id_manager_.numActiveChannels());
  ASSERT_OK(channel_id_manager_.bindChannelID(100, PeerLocalID{
                                                     .channel_id = 2, // remote peer's id
                                                     .local_peer = RemotePeer(),
                                                   }));
  auto interruptCallbackHandle =
    service_.getChannelCallbacks(100)
      .addInterruptCallback(
        [](absl::Status err, TransportCallbacks& transport_callbacks) {
          EXPECT_EQ(absl::InternalError("test error"), err);
          EXPECT_OK(transport_callbacks.sendMessageToConnection(wire::ChannelDataMsg{
            .recipient_channel = 1u, // note: manual channel id translation
            .data = "testing"_bytes,
          }));
        });

  // internal close sequence
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelDataMsg,
                                                      FIELD_EQ(recipient_channel, 1u),
                                                      FIELD_EQ(data, "testing"_bytes))))
    .WillOnce(Return(0));
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg,
                                                      FIELD_EQ(recipient_channel, 1u))))
    .WillOnce(InvokeWithoutArgs([&]() {
      EXPECT_OK(service_.handleMessage(wire::ChannelCloseMsg{
        .recipient_channel = 100,
      }));
      return 0;
    }));
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg,
                                      FIELD_EQ(recipient_channel, 2u)),
                                  _));

  ASSERT_TRUE(channel_id_manager_.isPreemptable(100, LocalPeer()));
  service_.preempt(service_.getChannelCallbacks(100), absl::InternalError("test error"));
}

TEST_P(ConnectionServiceTest, InterruptRemotePassthroughChannel) {
  EXPECT_CALL(transport_, streamId)
    .WillRepeatedly(Return(1));

  IN_SEQUENCE;
  auto internalChannel = *channel_id_manager_.allocateNewChannel(RemotePeer());
  uint32_t upstreamId = 10u;
  ASSERT_OK(channel_id_manager_.bindChannelID(
    internalChannel, PeerLocalID{
                       .channel_id = upstreamId,
                       .local_peer = RemotePeer(),
                     }));

  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg,
                                      FIELD_EQ(recipient_channel, upstreamId),
                                      FIELD_EQ(sender_channel, internalChannel)),
                                  _));

  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = internalChannel,
    .sender_channel = 1u,
  }));
  auto interruptCallbackHandle =
    service_.getChannelCallbacks(internalChannel)
      .addInterruptCallback(
        [](absl::Status err, TransportCallbacks& transport_callbacks) {
          EXPECT_EQ(absl::InternalError("test error"), err);
          EXPECT_OK(transport_callbacks.sendMessageToConnection(wire::ChannelDataMsg{
            .recipient_channel = 1u, // note: manual channel id translation
            .data = "testing"_bytes,
          }));
        });

  // internal close sequence
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelDataMsg,
                                                      FIELD_EQ(recipient_channel, 1u),
                                                      FIELD_EQ(data, "testing"_bytes))))
    .WillOnce(Return(0));
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg,
                                                      FIELD_EQ(recipient_channel, 1u))))
    .WillOnce(InvokeWithoutArgs([&]() {
      EXPECT_OK(service_.handleMessage(wire::ChannelCloseMsg{
        .recipient_channel = internalChannel,
      }));
      return 0;
    }));
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg,
                                      FIELD_EQ(recipient_channel, upstreamId)),
                                  _));

  ASSERT_TRUE(channel_id_manager_.isPreemptable(internalChannel, LocalPeer()));
  service_.preempt(service_.getChannelCallbacks(internalChannel), absl::InternalError("test error"));
}

TEST_P(ConnectionServiceTest, CloseLocalPassthroughChannelWithNoRemoteRef) {
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u),
                                      FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _))),
                                  _));

  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .sender_channel = 1, // local peer's ID
    .request = wire::SessionChannelOpenMsg{},
  }));
  ASSERT_EQ(1, channel_id_manager_.numActiveChannels());
  ASSERT_EQ(
    absl::InvalidArgumentError(
      fmt::format("error processing outgoing message of type ChannelClose (97): internal channel 100 is not known to {} (state: Pending)",
                  RemotePeer())),
    service_.handleMessage(wire::ChannelCloseMsg{
      .recipient_channel = 100,
    }));
  ASSERT_EQ(1, channel_id_manager_.numActiveChannels()); // the peer will stay in the Pending state
}

TEST_P(ConnectionServiceTest, CloseLocalPassthroughChannelWithRemoteRef) {
  IN_SEQUENCE;
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg,
                                      FIELD_EQ(sender_channel, 100u),
                                      FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _))),
                                  _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenMsg{
    .sender_channel = 1, // local peer's ID
    .request = wire::SessionChannelOpenMsg{},
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

TEST_P(ConnectionServiceTest, PreemptChannelCloseSequenceLocal) {
  EXPECT_CALL(transport_, streamId)
    .WillRepeatedly(Return(1));

  auto internalId = *channel_id_manager_.allocateNewChannel(RemotePeer());
  ASSERT_OK(channel_id_manager_.bindChannelID(internalId, PeerLocalID{
                                                            .channel_id = 1,
                                                            .local_peer = RemotePeer(),
                                                          }));
  testing::MockFunction<void(int)> check;
  {
    IN_SEQUENCE;
    EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg, _), _));
    EXPECT_CALL(check, Call(0));
    EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg, _)))
      .WillOnce(Return(0));
    EXPECT_CALL(check, Call(1));
    EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, _), _));
    EXPECT_CALL(check, Call(2));
  }

  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = internalId,
    .sender_channel = 2u,
  }));
  check.Call(0);

  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, LocalPeer()));

  service_.preempt(service_.getChannelCallbacks(internalId), absl::InternalError("test error"));
  check.Call(1);

  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internalId, LocalPeer()));

  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = internalId,
  }));
  check.Call(2);

  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(internalId, LocalPeer()));

  channel_id_manager_.releaseChannelID(internalId, RemotePeer());
  ASSERT_EQ(0uz, channel_id_manager_.numActiveChannels());
}

TEST_P(ConnectionServiceTest, PreemptChannelCloseSequenceRemote) {
  EXPECT_CALL(transport_, streamId)
    .WillRepeatedly(Return(1));

  auto internalId = *channel_id_manager_.allocateNewChannel(RemotePeer());
  ASSERT_OK(channel_id_manager_.bindChannelID(internalId, PeerLocalID{
                                                            .channel_id = 1,
                                                            .local_peer = RemotePeer(),
                                                          }));

  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg, _), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = internalId,
    .sender_channel = 2u,
  }));

  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, LocalPeer()));

  // Note: calling ChannelIDManager::preempt directly here is intentional to simulate the remote
  // peer's ConnectionService::preempt logic (which includes this, and other things that aren't
  // particularly relevant)
  channel_id_manager_.preempt(internalId, RemotePeer());

  // Simulate the effects of the remote peer close sequence as in the previous test
  channel_id_manager_.releaseChannelID(internalId, RemotePeer());

  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, LocalPeer()));

  // Assume the remote peer has forwarded a ChannelClose (we won't observe it directly)

  // Our local peer has replied with its own ChannelClose. This message should be dropped due to
  // the bereft state of the remote channel.
  // No callbacks expected
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = internalId,
  }));
  // Receiving the channel close above should have freed the internal channel
  ASSERT_EQ(0uz, channel_id_manager_.numActiveChannels());
}

TEST_P(ConnectionServiceTest, PreemptChannelCloseRace) {
  // Starting from a channel bound to both peers, one side preempts the channel (from the channel
  // id manager), but doesn't send a channel close yet. Then, the other side sends an unrelated
  // ChannelClose at the same time, which should go through. The first side sends their
  // ChannelClose, not knowing that the preempted channel has already been shut down by the other
  // side's forwarded ChannelClose. This second ChannelClose should be silently dropped. When the
  // close response is received from the preempted peer, it should then be forwarded.

  // Note: this scenario shouldn't occur normally since we always preempt and send the ChannelClose
  // at the same time. However, this is an important test of invariants.

  EXPECT_CALL(transport_, streamId)
    .WillRepeatedly(Return(1));

  auto internalId = *channel_id_manager_.allocateNewChannel(RemotePeer());
  ASSERT_OK(channel_id_manager_.bindChannelID(internalId, PeerLocalID{
                                                            .channel_id = 1,
                                                            .local_peer = RemotePeer(),
                                                          }));

  EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg, _), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = internalId,
    .sender_channel = 2u,
  }));

  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internalId, LocalPeer()));

  channel_id_manager_.preempt(internalId, LocalPeer());

  // simulate the other side sending a ChannelClose, followed by releasing their channel id
  wire::ChannelCloseMsg closeFromRemote{
    .recipient_channel = internalId,
  };
  auto ok = channel_id_manager_.processOutgoingChannelMsg(closeFromRemote, LocalPeer());
  ASSERT_OK(ok);
  ASSERT_TRUE(*ok); // this message will be forwarded
  channel_id_manager_.releaseChannelID(internalId, RemotePeer());

  ASSERT_EQ(ChannelIDState::Released, channel_id_manager_.peerState(internalId, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internalId, LocalPeer()));

  // this message should be dropped
  service_.getChannelCallbacks(internalId).sendMessageLocal(wire::ChannelCloseMsg{
    .recipient_channel = internalId,
  });

  // A response to the original ChannelClose is received, which should be forwarded since the
  // other side hasn't yet received a response to their ChannelClose
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, _), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = internalId,
  }));

  // Receiving the ChannelClose above should free the channel
  ASSERT_EQ(0uz, channel_id_manager_.numActiveChannels());
}

INSTANTIATE_TEST_SUITE_P(ConnectionService, ConnectionServiceTest,
                         testing::Values(Peer::Downstream, Peer::Upstream),
                         TestParameterNames({"Local_Downstream", "Local_Upstream"}));

// NOLINTBEGIN(readability-identifier-naming)
class ShutdownTest : public ConnectionServiceTest {
public:
  void SetUp() override {
    ConnectionServiceTest::SetUp();
    EXPECT_CALL(transport_, streamId)
      .WillRepeatedly(Return(1));
  }

  absl::StatusOr<std::pair<uint32_t, uint32_t>> NewRemoteOwnedChannel() {
    auto id = *channel_id_manager_.allocateNewChannel(RemotePeer());
    auto localId = next_local_id_++;
    RETURN_IF_NOT_OK(channel_id_manager_.bindChannelID(id, PeerLocalID{
                                                             .channel_id = localId,
                                                             .local_peer = RemotePeer(),
                                                           }));
    EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenConfirmationMsg,
                                        FIELD_EQ(sender_channel, id),
                                        FIELD_EQ(recipient_channel, localId)),
                                    _));
    RETURN_IF_NOT_OK(service_.handleMessage(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = id,
      .sender_channel = localId,
    }));

    EXPECT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(id, RemotePeer()));
    EXPECT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(id, LocalPeer()));
    return std::pair{id, localId};
  }

  absl::StatusOr<std::pair<uint32_t, uint32_t>> NewLocalOwnedChannel() {
    auto id = channel_id_manager_.nextInternalIdForTest();
    auto localId = next_local_id_++;
    EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg, FIELD_EQ(sender_channel, id)), _));
    RETURN_IF_NOT_OK(service_.handleMessage(wire::ChannelOpenMsg{
      .sender_channel = localId,
      .request = wire::SessionChannelOpenMsg{},
    }));
    RETURN_IF_NOT_OK(channel_id_manager_.bindChannelID(id, PeerLocalID{
                                                             .channel_id = localId,
                                                             .local_peer = RemotePeer(),
                                                           }));

    EXPECT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(id, RemotePeer()));
    EXPECT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(id, LocalPeer()));
    return std::pair{id, localId};
  }

  absl::StatusOr<std::pair<uint32_t, uint32_t>> NewLocalOwnedPendingChannel() {
    auto id = channel_id_manager_.nextInternalIdForTest();
    auto localId = next_local_id_++;
    EXPECT_CALL(transport_, forward(MSG(wire::ChannelOpenMsg, FIELD_EQ(sender_channel, id)), _));
    RETURN_IF_NOT_OK(service_.handleMessage(wire::ChannelOpenMsg{
      .sender_channel = localId,
      .request = wire::SessionChannelOpenMsg{},
    }));

    EXPECT_EQ(ChannelIDState::Pending, channel_id_manager_.peerState(id, RemotePeer()));
    EXPECT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(id, LocalPeer()));
    return std::pair{id, localId};
  }

private:
  uint32_t next_local_id_{0};
};
// NOLINTEND(readability-identifier-naming)

TEST_P(ShutdownTest, Shutdown) {
  // Channels 1 and 2 are normal, bound by both peers
  auto [channel1, channel1Local] = *NewRemoteOwnedChannel();
  auto [channel2, channel2Local] = *NewLocalOwnedChannel();

  // Set up channel 3 to receive a ChannelClose message from the local peer. Upon shutdown, the
  // system should just wait for the channel to close normally.
  auto [channel3, channel3Local] = *NewLocalOwnedChannel();
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel3Local)), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channel3,
  }));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel3, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Released, channel_id_manager_.peerState(channel3, LocalPeer()));

  // Set up channel 4 to be already preempted and awaiting a ChannelClose reply locally.
  auto [channel4, channel4Local] = *NewLocalOwnedChannel();
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel4Local))))
    .WillOnce(Return(0));
  service_.preempt(service_.getChannelCallbacks(channel4), absl::CancelledError("test error"));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel4, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(channel4, LocalPeer()));

  // Set up channel 5 to be pending open
  auto [channel5, channel5Local] = *NewLocalOwnedPendingChannel();

  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel1Local))))
    .WillOnce(Return(0));
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel2Local))))
    .WillOnce(Return(0));
  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel5Local))))
    .WillOnce(Return(0));
  service_.shutdown(absl::InternalError("shutdown"));
  // Calling shutdown() a second time should do nothing, as no channels should be eligible for
  // preemption anymore. The drain callback does get added a second time, but the previous handle
  // is destroyed at the same time, so it is still only called once.
  service_.shutdown(absl::InternalError("shutdown"));

  // 1/2/5 should change to preempted
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel1, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(channel1, LocalPeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel2, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(channel2, LocalPeer()));
  ASSERT_EQ(ChannelIDState::Pending, channel_id_manager_.peerState(channel5, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(channel5, LocalPeer()));

  // 3/4 should not change
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel3, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Released, channel_id_manager_.peerState(channel3, LocalPeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel4, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(channel4, LocalPeer()));

  ASSERT_EQ(5u, channel_id_manager_.numActiveChannels());

  // Channel 1 reply
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel1Local)), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channel1,
  }));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel1, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(channel1, LocalPeer()));
  channel_id_manager_.releaseChannelID(channel1, RemotePeer());
  ASSERT_EQ(4u, channel_id_manager_.numActiveChannels());

  // Channel 2 reply
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel2Local)), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channel2,
  }));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel2, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(channel2, LocalPeer()));
  channel_id_manager_.releaseChannelID(channel2, RemotePeer());
  ASSERT_EQ(3u, channel_id_manager_.numActiveChannels());

  // Channel 5 reply (note: this should not forward; the peer is still pending)
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channel5,
  }));
  ASSERT_EQ(ChannelIDState::Pending, channel_id_manager_.peerState(channel5, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(channel5, LocalPeer()));

  // At this point, the shutdown sequence is waiting for the "out-of-band" channel closures to
  // be completed

  // Channel 4 reply
  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel4Local)), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channel4,
  }));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel4, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(channel4, LocalPeer()));
  channel_id_manager_.releaseChannelID(channel4, RemotePeer());
  ASSERT_EQ(2u, channel_id_manager_.numActiveChannels());

  // Channel 3 closed by the remote peer
  channel_id_manager_.releaseChannelID(channel3, RemotePeer());
  ASSERT_EQ(1u, channel_id_manager_.numActiveChannels());

  // Resolve channel 5 - the peer could either ChannelOpenConfirmation/Failure, but from our
  // perspective it doesn't matter, it will eventually close the channel and release its id.
  EXPECT_CALL(transport_, terminate(absl::InternalError("shutdown")));
  channel_id_manager_.releaseChannelID(channel5, RemotePeer());
  ASSERT_EQ(0u, channel_id_manager_.numActiveChannels()); // completes the shutdown
}

TEST_P(ShutdownTest, ShutdownAfterDrainCalledSomewhereElse) {
  auto [channel1, channel1Local] = *NewRemoteOwnedChannel();
  bool called{};
  auto handle = channel_id_manager_.startDrain(mock_dispatcher_, [&called] {
    called = true;
  });

  EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel1Local))))
    .WillOnce(Return(0));
  service_.shutdown(absl::InternalError("shutdown"));

  EXPECT_CALL(transport_, forward(MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, channel1Local)), _));
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channel1,
  }));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(channel1, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bereft, channel_id_manager_.peerState(channel1, LocalPeer()));

  ASSERT_FALSE(called);
  EXPECT_CALL(transport_, terminate(absl::InternalError("shutdown")));
  channel_id_manager_.releaseChannelID(channel1, RemotePeer());
  ASSERT_TRUE(called);
}

TEST_P(ShutdownTest, ShutdownAfterDrainAlreadyCompleted) {
  bool called{};
  auto handle = channel_id_manager_.startDrain(mock_dispatcher_, [&called] {
    called = true;
  });
  ASSERT_TRUE(called);

  EXPECT_CALL(transport_, terminate(absl::InternalError("shutdown")));
  service_.shutdown(absl::InternalError("shutdown"));
}

INSTANTIATE_TEST_SUITE_P(Shutdown, ShutdownTest,
                         testing::Values(Peer::Downstream, Peer::Upstream),
                         TestParameterNames({"Local_Downstream", "Local_Upstream"}));

// NOLINTBEGIN(readability-identifier-naming)
class ChannelOpenPreemptRaceTest : public ConnectionServiceTest {
public:
  using ConnectionServiceTest::ConnectionServiceTest;
  void SetUp() override {
    ConnectionServiceTest::SetUp();
    EXPECT_CALL(transport_, streamId)
      .WillRepeatedly(Return(1));

    internal_id_ = *channel_id_manager_.allocateNewChannel(RemotePeer());
    // Simulate a channel being created by the peer. Our channel's state will be Pending
    ASSERT_OK(channel_id_manager_.bindChannelID(internal_id_, PeerLocalID{
                                                                .channel_id = 1,
                                                                .local_peer = RemotePeer(),
                                                              }));

    ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internal_id_, RemotePeer()));
    ASSERT_EQ(ChannelIDState::Pending, channel_id_manager_.peerState(internal_id_, LocalPeer()));

    // Simulate the remote peer preempting the channel
    channel_id_manager_.preempt(internal_id_, RemotePeer());

    ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internal_id_, RemotePeer()));
    ASSERT_EQ(ChannelIDState::Pending, channel_id_manager_.peerState(internal_id_, LocalPeer()));
  }

  absl::Status ReceiveChannelOpenConfirmation() {
    testing::MockFunction<void()> check;
    {
      IN_SEQUENCE;
      EXPECT_CALL(transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg,
                                                          FIELD_EQ(recipient_channel, 2u))))
        .WillOnce(Return(0));
      EXPECT_CALL(check, Call);
    }

    auto stat = service_.handleMessage(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = internal_id_,
      .sender_channel = 2,
      .initial_window_size = wire::ChannelWindowSize,
      .max_packet_size = wire::ChannelMaxPacketSize,
    });
    check.Call();

    return stat;
  }

protected:
  uint32_t internal_id_;
};
// NOLINTEND(readability-identifier-naming)

TEST_P(ChannelOpenPreemptRaceTest, ChannelOpenConfirmation) {
  // While the remote peer is in the Preempted state, our ChannelOpenConfirmation comes in.
  // This should initiate a close sequence locally, ignoring the remote peer
  ASSERT_OK(ReceiveChannelOpenConfirmation());

  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internal_id_, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internal_id_, LocalPeer()));

  // Then, the upstream responds with its own ChannelClose. The remote is stil in Preempted
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = internal_id_,
  }));

  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internal_id_, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Released, channel_id_manager_.peerState(internal_id_, LocalPeer()));

  // Lastly, simulate the remote peer preemption finalized
  channel_id_manager_.releaseChannelID(internal_id_, RemotePeer());

  // The channel should be freed now
  ASSERT_EQ(0uz, channel_id_manager_.numActiveChannels());
}

TEST_P(ChannelOpenPreemptRaceTest, ChannelOpenFailure) {
  // While the remote peer is in the Preempted state, our ChannelOpenFailure comes in.
  // This doesn't initiate a close sequence, and the state should immediately transition to Released

  ASSERT_OK(service_.handleMessage(wire::ChannelOpenFailureMsg{
    .recipient_channel = internal_id_,
    .description = "example"s,
  }));

  // Note that Preempted on the remote peer state holds the internal id alive
  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internal_id_, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Released, channel_id_manager_.peerState(internal_id_, LocalPeer()));

  channel_id_manager_.releaseChannelID(internal_id_, RemotePeer());
  ASSERT_EQ(0uz, channel_id_manager_.numActiveChannels());
}

TEST_P(ChannelOpenPreemptRaceTest, IgnoreMessagesBeforeChannelClose) {
  // While the remote peer is in the Preempted state, the channel is opened, which initiates the
  // close sequence. The local peer sends other channel messages it might have had queued up before
  // responding to our ChannelClose request. These messages should be ignored.
  ASSERT_OK(ReceiveChannelOpenConfirmation());

  // Any channel message other than ChannelClose should be dropped
  ASSERT_OK(service_.handleMessage(wire::ChannelRequestMsg{
    .recipient_channel = internal_id_,
    .want_reply = true,
    .request = wire::ShellChannelRequestMsg{},
  }));

  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internal_id_, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Bound, channel_id_manager_.peerState(internal_id_, LocalPeer()));

  // The channel should be closed after ChannelClose is eventually received
  ASSERT_OK(service_.handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = internal_id_,
  }));

  ASSERT_EQ(ChannelIDState::Preempted, channel_id_manager_.peerState(internal_id_, RemotePeer()));
  ASSERT_EQ(ChannelIDState::Released, channel_id_manager_.peerState(internal_id_, LocalPeer()));

  channel_id_manager_.releaseChannelID(internal_id_, RemotePeer());
  ASSERT_EQ(0uz, channel_id_manager_.numActiveChannels());
}

INSTANTIATE_TEST_SUITE_P(ChannelOpenPreemptRace, ChannelOpenPreemptRaceTest,
                         testing::Values(Peer::Downstream, Peer::Upstream),
                         TestParameterNames({"Local_Downstream", "Local_Upstream"}));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec