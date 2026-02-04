#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <cstdlib>

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/test_common.h"

// Note: these tests are separate from the regular ConnectionService tests, due to the dependency
// on MockServerFactoryContext which triples compile time

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

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

// Note: most functionality in this class is tested in server_transport_test
class DownstreamConnectionServiceTest : public testing::Test {
public:
  DownstreamConnectionServiceTest() {
    transport_ = std::make_unique<testing::StrictMock<MockDownstreamTransportCallbacks>>();
    service_ = std::make_unique<DownstreamConnectionService>(*transport_, std::make_shared<StreamTracker>(context_));
    service_->registerMessageHandlers(msg_dispatcher_);

    EXPECT_CALL(*transport_, streamId)
      .WillRepeatedly(Return(1));
    EXPECT_CALL(*transport_, channelIdManager)
      .WillRepeatedly(ReturnRef(channel_id_manager_));
    EXPECT_CALL(*transport_, secretsProvider)
      .WillRepeatedly(ReturnRef(secrets_provider_));
    EXPECT_CALL(*transport_, statsScope)
      .Times(AnyNumber());
    EXPECT_CALL(*transport_, connectionDispatcher)
      .WillRepeatedly([this] -> Envoy::OptRef<Envoy::Event::Dispatcher> {
        return mock_dispatcher_;
      });
  }

protected:
  NiceMock<Envoy::Event::MockDispatcher> mock_dispatcher_; // field order is important
  ChannelIDManager channel_id_manager_{100, 100};
  TestSecretsProvider secrets_provider_;
  TestSshMessageDispatcher msg_dispatcher_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  std::unique_ptr<testing::StrictMock<MockDownstreamTransportCallbacks>> transport_;
  std::unique_ptr<DownstreamConnectionService> service_;
};

TEST_F(DownstreamConnectionServiceTest, TestSendChannelEvent) {
  pomerium::extensions::ssh::ChannelEvent ev1;
  ev1.mutable_internal_channel_opened()->set_hostname("foo");
  ev1.mutable_internal_channel_opened()->set_channel_id(1234);

  pomerium::extensions::ssh::ChannelEvent ev2;
  ev2.mutable_internal_channel_closed()->set_channel_id(1234);
  ev2.mutable_internal_channel_closed()->set_reason("foo");

  pomerium::extensions::ssh::ChannelEvent ev3;
  ev3.mutable_channel_stats()->mutable_stats_list()->add_items()->set_channel_id(1234);

  for (const auto& ev : {ev1, ev2, ev3}) {
    pomerium::extensions::ssh::StreamEvent expectedEvent;
    expectedEvent.mutable_channel_event()->CopyFrom(ev);

    pomerium::extensions::ssh::ClientMessage msg;
    EXPECT_CALL(*transport_, sendMgmtClientMessage(_))
      .WillOnce(SaveArg<0>(&msg));

    service_->sendChannelEvent(ev);
    EXPECT_THAT(msg.event().channel_event(), Envoy::ProtoEq(ev));
  }

  pomerium::extensions::ssh::ChannelEvent empty;
  EXPECT_THROW_WITH_MESSAGE(service_->sendChannelEvent(empty),
                            Envoy::EnvoyException,
                            "invalid channel event");
}

TEST_F(DownstreamConnectionServiceTest, TestReceiveInvalidServerMessage) {
  EXPECT_EQ(absl::InternalError("invalid server message"),
            service_->handleMessage(std::make_unique<ServerMessage>()));
}

TEST_F(DownstreamConnectionServiceTest, TestStatsTimer) {
  NiceMock<Network::MockConnection> mock_connection;
  EXPECT_CALL(mock_connection, dispatcher)
    .WillRepeatedly(ReturnRef(mock_dispatcher_));
  auto* timer = new Envoy::Event::MockTimer(&mock_dispatcher_);
  EXPECT_CALL(*timer, enableTimer);
  service_->onStreamBegin(mock_connection);

  auto ch1 = std::make_unique<NiceMock<MockChannel>>();
  MockChannelStatsProvider ch1Stats;
  EXPECT_CALL(*ch1, setChannelCallbacks)
    .WillOnce([ch1 = ch1.get(), &ch1Stats](ChannelCallbacks& cb) {
      ch1->Channel::setChannelCallbacks(cb).IgnoreError();
      cb.setStatsProvider(ch1Stats);
      return absl::OkStatus();
    });
  EXPECT_CALL(ch1Stats, populateChannelStats)
    .WillRepeatedly(Invoke([](pomerium::extensions::ssh::ChannelStats& stats) {
      stats.set_rx_bytes_total(1);
      stats.set_tx_bytes_total(1);
    }));

  auto ch2 = std::make_unique<NiceMock<MockChannel>>();
  MockChannelStatsProvider ch2Stats;
  EXPECT_CALL(*ch2, setChannelCallbacks)
    .WillOnce([ch2 = ch2.get(), &ch2Stats](ChannelCallbacks& cb) {
      ch2->Channel::setChannelCallbacks(cb).IgnoreError();
      cb.setStatsProvider(ch2Stats);
      return absl::OkStatus();
    });
  EXPECT_CALL(ch2Stats, populateChannelStats)
    .WillRepeatedly(Invoke([](pomerium::extensions::ssh::ChannelStats& stats) {
      stats.set_rx_bytes_total(2);
      stats.set_tx_bytes_total(2);
    }));
  auto ch3 = std::make_unique<NiceMock<MockChannel>>();

  ASSERT_OK(service_->startChannel(std::move(ch1)));
  ASSERT_OK(service_->startChannel(std::move(ch2)));
  ASSERT_OK(service_->startChannel(std::move(ch3)));

  pomerium::extensions::ssh::ClientMessage msg;
  EXPECT_CALL(*transport_, sendMgmtClientMessage(_))
    .WillOnce(SaveArg<0>(&msg));

  EXPECT_CALL(*timer, enableTimer);
  timer->invokeCallback();

  ASSERT_TRUE(msg.event().channel_event().channel_stats().has_stats_list());
  ASSERT_EQ(2, msg.event().channel_event().channel_stats().stats_list().items_size());

  auto stats1 = msg.event().channel_event().channel_stats().stats_list().items(0);
  auto stats2 = msg.event().channel_event().channel_stats().stats_list().items(1);
  if (stats1.channel_id() == 101) {
    std::swap(stats1, stats2);
  }
  EXPECT_EQ(100, stats1.channel_id());
  EXPECT_EQ(1, stats1.rx_bytes_total());
  EXPECT_EQ(1, stats1.tx_bytes_total());
  EXPECT_EQ(101, stats2.channel_id());
  EXPECT_EQ(2, stats2.rx_bytes_total());
  EXPECT_EQ(2, stats2.tx_bytes_total());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec