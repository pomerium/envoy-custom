#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/test_common/test_common.h"
#include "test/mocks/event/mocks.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

TEST(ChannelIDManagerTest, AllocateNewChannel) {
  ChannelIDManager mgr(10);
  for (uint32_t i = 0; i < 10; i++) {
    ASSERT_EQ(10u + i, mgr.nextInternalIdForTest());
    auto id = mgr.allocateNewChannel(Peer::Downstream);
    ASSERT_OK(id);
    ASSERT_EQ(10u + i, *id);
    ASSERT_EQ(1uz + i, mgr.numActiveChannels());
  }
}

TEST(ChannelIDManagerTest, AllocateNewChannelError) {
  ChannelIDManager mgr(10, 1);
  ASSERT_OK(mgr.allocateNewChannel(Peer::Downstream));
  ASSERT_EQ(absl::ResourceExhaustedError("failed to allocate ID"),
            mgr.allocateNewChannel(Peer::Downstream).status());
}

TEST(ChannelIDManagerTest, Owner) {
  ChannelIDManager mgr(10);
  {
    auto id = mgr.allocateNewChannel(Peer::Downstream);
    ASSERT_OK(id);
    auto owner = mgr.owner(*id);
    ASSERT_EQ(Peer::Downstream, *owner);
  }
  {
    auto id = mgr.allocateNewChannel(Peer::Upstream);
    ASSERT_OK(id);
    auto owner = mgr.owner(*id);
    ASSERT_EQ(Peer::Upstream, *owner);
  }
}

TEST(ChannelIDManagerTest, Owner_UnknownChannel) {
  ChannelIDManager mgr(10);
  auto owner = mgr.owner(10);
  ASSERT_FALSE(owner.has_value());
}

TEST(ChannelIDManagerTest, BindChannelID) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  EXPECT_EQ(ChannelIDState::Unbound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Unbound, *mgr.peerState(*id, Peer::Upstream));

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));

  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Pending, *mgr.peerState(*id, Peer::Upstream));

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Upstream));
}

TEST(ChannelIDManagerTest, BindChannelID_NoExpectRemote) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  EXPECT_EQ(ChannelIDState::Unbound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Unbound, *mgr.peerState(*id, Peer::Upstream));

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   },
                              false));

  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Unbound, *mgr.peerState(*id, Peer::Upstream));

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Upstream));
}

TEST(ChannelIDManagerTest, BindChannelID_UnknownChannel) {
  ChannelIDManager mgr(10);
  ASSERT_EQ(absl::InvalidArgumentError("unknown channel 1"),
            mgr.bindChannelID(1, PeerLocalID{
                                   .channel_id = 1,
                                   .local_peer = Peer::Downstream,
                                 }));
  ASSERT_EQ(absl::InvalidArgumentError("unknown channel 10"),
            mgr.bindChannelID(10, PeerLocalID{
                                    .channel_id = 1,
                                    .local_peer = Peer::Downstream,
                                  }));
}

TEST(ChannelIDManagerTest, BindChannelID_AlreadyBound) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_EQ(absl::InvalidArgumentError("channel 10 is already known to Downstream"),
            mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
}

TEST(ChannelIDManagerTest, BindAndReleaseChannelID) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Upstream));

  mgr.releaseChannelID(*id, Peer::Upstream);

  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Released, *mgr.peerState(*id, Peer::Upstream));

  mgr.releaseChannelID(*id, Peer::Downstream);
  EXPECT_EQ(std::nullopt, mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(std::nullopt, mgr.peerState(*id, Peer::Upstream));
}

TEST(ChannelIDManagerTest, ProcessOutgoingChannelMsg) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  {
    wire::ChannelDataMsg msg;
    msg.recipient_channel = *id;
    ASSERT_OK(mgr.processOutgoingChannelMsg(msg, Peer::Downstream));
    EXPECT_EQ(1u, msg.recipient_channel);
  }
  {
    wire::ChannelDataMsg msg;
    msg.recipient_channel = *id;
    ASSERT_OK(mgr.processOutgoingChannelMsg(msg, Peer::Upstream));
    EXPECT_EQ(2u, msg.recipient_channel);
  }
}

TEST(ChannelIDManagerTest, ProcessOutgoingChannelMsg_NoSuchChannel) {
  ChannelIDManager mgr(10);
  wire::ChannelDataMsg msg;
  msg.recipient_channel = 10;
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): no such channel: 10"),
            mgr.processOutgoingChannelMsg(msg, Peer::Downstream).status());
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): no such channel: 10"),
            mgr.processOutgoingChannelMsg(msg, Peer::Upstream).status());
}

TEST(ChannelIDManagerTest, ProcessOutgoingChannelMsg_ChannelIDNotBound) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  wire::ChannelDataMsg msg;
  msg.recipient_channel = 10;

  // try processing the messages before binding the IDs
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): internal channel 10 is not known to Downstream (state: Unbound)"),
            mgr.processOutgoingChannelMsg(msg, Peer::Downstream).status());
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): internal channel 10 is not known to Upstream (state: Unbound)"),
            mgr.processOutgoingChannelMsg(msg, Peer::Upstream).status());

  // bind the IDs
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  // try processing the messages again
  ASSERT_OK(mgr.processOutgoingChannelMsg(msg, Peer::Downstream));
  EXPECT_EQ(1u, *msg.recipient_channel);
  msg.recipient_channel = 10; // reset
  ASSERT_OK(mgr.processOutgoingChannelMsg(msg, Peer::Upstream));
  EXPECT_EQ(2u, *msg.recipient_channel);
}

TEST(ChannelIDManagerTest, ProcessOutgoingChannelMsg_ChannelIDReleased) {
  // Do this test twice, but vary the order in which IDs are released to cover all branches
  auto releaseOrders = std::vector<std::pair<Peer, Peer>>{{Peer::Downstream, Peer::Upstream},
                                                          {Peer::Upstream, Peer::Downstream}};

  for (auto releaseOrder : releaseOrders) {
    auto [a, b] = releaseOrder;
    ChannelIDManager mgr(10);
    auto id = mgr.allocateNewChannel(Peer::Downstream);
    ASSERT_OK(id);
    ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                       .channel_id = 1,
                                       .local_peer = Peer::Downstream,
                                     }));
    ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                       .channel_id = 2,
                                       .local_peer = Peer::Upstream,
                                     }));

    // release one of the bound IDs - this should not release the internal ID yet
    mgr.releaseChannelID(*id, a);
    {
      wire::ChannelDataMsg msg;
      msg.recipient_channel = *id;
      ASSERT_OK(mgr.processOutgoingChannelMsg(msg, a));
    }
    {
      wire::ChannelDataMsg msg;
      msg.recipient_channel = *id;
      ASSERT_OK(mgr.processOutgoingChannelMsg(msg, b));
    }

    // release the other bound ID, which should release the internal ID
    mgr.releaseChannelID(*id, b);
    wire::ChannelDataMsg msg;
    msg.recipient_channel = 10;
    ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): no such channel: 10"),
              mgr.processOutgoingChannelMsg(msg, a).status());
    ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): no such channel: 10"),
              mgr.processOutgoingChannelMsg(msg, b).status());
  }
}

TEST(ChannelIDManagerTest, ProcessOutgoingChannelMsg_DropChannelClose) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  mgr.preempt(*id, Peer::Downstream);
  wire::ChannelCloseMsg close{
    .recipient_channel = *id,
  };
  auto send = mgr.processOutgoingChannelMsg(close, Peer::Upstream);
  ASSERT_OK(send);
  ASSERT_FALSE(*send);
}

TEST(ChannelIDManagerTest, Drain) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  NiceMock<Envoy::Event::MockDispatcher> dispatcher;
  Envoy::Common::CallbackHandlePtr cbHandle;
  bool called{};
  cbHandle = mgr.startDrain(dispatcher, [&] {
    called = true;
  });
  ASSERT_FALSE(called);

  ASSERT_EQ(absl::UnavailableError("server is shutting down"), mgr.allocateNewChannel(Peer::Downstream).status());
  ASSERT_EQ(absl::UnavailableError("server is shutting down"), mgr.allocateNewChannel(Peer::Upstream).status());

  mgr.releaseChannelID(*id, Peer::Downstream);
  ASSERT_FALSE(called);
  mgr.releaseChannelID(*id, Peer::Upstream);
  ASSERT_TRUE(called);
}

TEST(ChannelIDManagerTest, Drain_NoChannels) {
  ChannelIDManager mgr(10);
  NiceMock<Envoy::Event::MockDispatcher> dispatcher;

  CHECK_CALLED({
    auto handle = mgr.startDrain(dispatcher, [&] {
      CALLED;
    });
  });
}

TEST(ChannelIDManagerTest, Drain_AlreadyDraining) {
  ChannelIDManager mgr(10);
  NiceMock<Envoy::Event::MockDispatcher> dispatcher;
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   },
                              false));
  bool called1{};
  bool called2{};
  auto cbHandle1 = mgr.startDrain(dispatcher, [&] {
    called1 = true;
  });
  auto cbHandle2 = mgr.startDrain(dispatcher, [&] {
    called2 = true;
  });

  ASSERT_FALSE(called1);
  ASSERT_FALSE(called2);
  mgr.releaseChannelID(*id, Peer::Downstream);
  ASSERT_TRUE(called1);

  CHECK_CALLED({
    EXPECT_EQ(nullptr, mgr.startDrain(dispatcher, [&] {
      CALLED;
    }));
  });
}

TEST(ChannelIDManagerTest, Drain_PendingState) {
  ChannelIDManager mgr(10);
  NiceMock<Envoy::Event::MockDispatcher> dispatcher;
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  Envoy::Common::CallbackHandlePtr cbHandle;
  bool called{};
  cbHandle = mgr.startDrain(dispatcher, [&] {
    called = true;
  });
  ASSERT_FALSE(called);

  mgr.releaseChannelID(*id, Peer::Downstream);
  ASSERT_FALSE(called); // pending channels should keep the id alive
}

TEST(ChannelIDManagerTest, Preempt) {
  ChannelIDManager mgr(10);

  ASSERT_FALSE(mgr.isPreemptable(100, Peer::Downstream));

  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  ASSERT_TRUE(mgr.isPreemptable(*id, Peer::Downstream));
  mgr.preempt(*id, Peer::Downstream);
  mgr.releaseChannelID(*id, Peer::Downstream);

  EXPECT_EQ(ChannelIDState::Bereft, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Upstream));

  {
    wire::ChannelDataMsg msg;
    msg.recipient_channel = *id;
    auto send = mgr.processOutgoingChannelMsg(msg, Peer::Downstream);
    ASSERT_OK(send);
    ASSERT_FALSE(*send);
    EXPECT_EQ(*id, msg.recipient_channel);
  }
  {
    wire::ChannelDataMsg msg;
    msg.recipient_channel = *id;
    ASSERT_OK(mgr.processOutgoingChannelMsg(msg, Peer::Upstream));
    EXPECT_EQ(2u, msg.recipient_channel);
  }

  mgr.releaseChannelID(*id, Peer::Upstream);
  EXPECT_EQ(0uz, mgr.numActiveChannels());
}

TEST(ChannelIDManagerTest, PreemptCloseTracking) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  EXPECT_FALSE(mgr.isPreemptable(*id, Peer::Downstream));
  EXPECT_FALSE(mgr.isPreemptable(*id, Peer::Upstream));

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));

  EXPECT_TRUE(mgr.isPreemptable(*id, Peer::Downstream));
  EXPECT_FALSE(mgr.isPreemptable(*id, Peer::Upstream));

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));

  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Upstream));

  EXPECT_TRUE(mgr.isPreemptable(*id, Peer::Downstream));
  EXPECT_TRUE(mgr.isPreemptable(*id, Peer::Upstream));

  mgr.preempt(*id, Peer::Downstream);

  EXPECT_EQ(ChannelIDState::Preempted, *mgr.peerState(*id, Peer::Downstream));
  EXPECT_EQ(ChannelIDState::Bound, *mgr.peerState(*id, Peer::Upstream));

  {
    wire::ChannelDataMsg data{
      .recipient_channel = *id,
    };
    ASSERT_TRUE(*mgr.processOutgoingChannelMsg(data, Peer::Downstream));

    wire::ChannelCloseMsg close{
      .recipient_channel = *id,
    };
    ASSERT_TRUE(*mgr.processOutgoingChannelMsg(close, Peer::Downstream));
  }

  {
    wire::ChannelDataMsg data{
      .recipient_channel = *id,
    };
    ASSERT_FALSE(*mgr.processOutgoingChannelMsg(data, Peer::Downstream));

    wire::ChannelCloseMsg close{
      .recipient_channel = *id,
    };
    ASSERT_FALSE(*mgr.processOutgoingChannelMsg(close, Peer::Downstream));
  }
}

class ChannelIDManagerFormatTest : public testing::TestWithParam<std::tuple<ChannelIDState, ChannelIDState, Peer>> {
};
TEST_P(ChannelIDManagerFormatTest, Formatting) {
  // the specific format is not worth testing for, but we can make sure that the custom formatter
  // does not crash when constructing its format string
  auto [stateA, stateB, owner] = GetParam();
  InternalChannelInfo info{
    .peer_ids = {1, 2},
    .peer_states = {stateA, stateB},
    .owner = owner,
  };
  ASSERT_NO_THROW((void)fmt::to_string(info));
}

INSTANTIATE_TEST_SUITE_P(ChannelIDManagerFormat, ChannelIDManagerFormatTest,
                         testing::Combine(
                           testing::Values(ChannelIDState::Unbound, ChannelIDState::Bound, ChannelIDState::Released),
                           testing::Values(ChannelIDState::Unbound, ChannelIDState::Bound, ChannelIDState::Released),
                           testing::Values(Peer::Downstream, Peer::Upstream)));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
