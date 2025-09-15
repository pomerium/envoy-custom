#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/test_common/test_common.h"
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

  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 1,
                                     .local_peer = Peer::Downstream,
                                   }));
  ASSERT_OK(mgr.bindChannelID(*id, PeerLocalID{
                                     .channel_id = 2,
                                     .local_peer = Peer::Upstream,
                                   }));
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
  EXPECT_NO_THROW({
    mgr.releaseChannelID(*id, Peer::Downstream);
    mgr.releaseChannelID(*id, Peer::Upstream);
  });
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
            mgr.processOutgoingChannelMsg(msg, Peer::Downstream));
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): no such channel: 10"),
            mgr.processOutgoingChannelMsg(msg, Peer::Upstream));
}

TEST(ChannelIDManagerTest, ProcessOutgoingChannelMsg_ChannelIDNotBound) {
  ChannelIDManager mgr(10);
  auto id = mgr.allocateNewChannel(Peer::Downstream);
  ASSERT_OK(id);

  wire::ChannelDataMsg msg;
  msg.recipient_channel = 10;

  // try processing the messages before binding the IDs
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): internal channel 10 is not known to Downstream (state: Unbound)"),
            mgr.processOutgoingChannelMsg(msg, Peer::Downstream));
  ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): internal channel 10 is not known to Upstream (state: Unbound)"),
            mgr.processOutgoingChannelMsg(msg, Peer::Upstream));

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
              mgr.processOutgoingChannelMsg(msg, a));
    ASSERT_EQ(absl::InvalidArgumentError("error processing outgoing message of type ChannelData (94): no such channel: 10"),
              mgr.processOutgoingChannelMsg(msg, b));
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
  ASSERT_NO_THROW(fmt::to_string(info));
}

INSTANTIATE_TEST_SUITE_P(ChannelIDManagerFormat, ChannelIDManagerFormatTest,
                         testing::Combine(
                           testing::Values(ChannelIDState::Unbound, ChannelIDState::Bound, ChannelIDState::Released),
                           testing::Values(ChannelIDState::Unbound, ChannelIDState::Bound, ChannelIDState::Released),
                           testing::Values(Peer::Downstream, Peer::Upstream)));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
