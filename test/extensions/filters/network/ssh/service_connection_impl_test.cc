#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <cstdlib>

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/channel_filter_config.h"
#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/test_common.h"
#include "test/test_common/registry.h"

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
    service_ = std::make_unique<UpstreamConnectionService>(ConnectionServiceOptions{}, *transport_);
    channel_filter_manager_ = std::make_unique<ChannelFilterManager>(ExtensionConfigList{}, context_);
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
    EXPECT_CALL(*transport_, channelFilterManager)
      .Times(AnyNumber())
      .WillRepeatedly([this] -> ChannelFilterManager& {
        return *channel_filter_manager_;
      });
  }

protected:
  NiceMock<Envoy::Event::MockDispatcher> mock_dispatcher_; // field order is important
  ChannelIDManager channel_id_manager_{100, 100};
  TestSecretsProvider secrets_provider_;
  TestSshMessageDispatcher msg_dispatcher_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  std::unique_ptr<ChannelFilterManager> channel_filter_manager_;
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
    service_ = std::make_unique<DownstreamConnectionService>(ConnectionServiceOptions{}, *transport_, std::make_shared<StreamTracker>(context_));
    channel_filter_manager_ = std::make_unique<ChannelFilterManager>(ExtensionConfigList{}, context_);
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
    EXPECT_CALL(*transport_, channelFilterManager)
      .Times(AnyNumber())
      .WillRepeatedly([this] -> ChannelFilterManager& {
        return *channel_filter_manager_;
      });
  }

protected:
  NiceMock<Envoy::Event::MockDispatcher> mock_dispatcher_; // field order is important
  ChannelIDManager channel_id_manager_{100, 100};
  TestSecretsProvider secrets_provider_;
  TestSshMessageDispatcher msg_dispatcher_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  std::unique_ptr<ChannelFilterManager> channel_filter_manager_;
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
      ch1->Channel::setChannelCallbacks(cb);
      cb.setStatsProvider(ch1Stats);
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
      ch2->Channel::setChannelCallbacks(cb);
      cb.setStatsProvider(ch2Stats);
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

TEST_F(DownstreamConnectionServiceTest, TestChannelReadFilters) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  IN_SEQUENCE;

  auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
  auto filter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([&] {
      return std::move(factory);
    });

  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  ChannelFilterCallbacks* channelFilterCallbacks{};
  ChannelCallbacks* ch1Callbacks{};
  auto channelId = *channel_id_manager_.allocateNewChannel(Peer::Downstream);

  EXPECT_CALL(*factory, createEmptyConfigProto)
    .WillOnce([] {
      return std::make_unique<Envoy::Protobuf::StringValue>();
    });
  EXPECT_CALL(*factory, createReadFilter)
    .WillOnce([&](const google::protobuf::Message& config, ChannelFilterCallbacks& filter_callbacks) {
      EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
      EXPECT_EQ(static_cast<stream_id_t>(1), filter_callbacks.streamId());
      channelFilterCallbacks = &filter_callbacks;
      EXPECT_EQ(channelId, filter_callbacks.channelId());
      // no channel open message has been received yet, so channelType should return nullopt
      EXPECT_EQ(std::nullopt, filter_callbacks.channelType());
      return std::move(filter);
    });
  EXPECT_CALL(*ch1, setChannelCallbacks)
    .WillOnce([ch1 = ch1.get(), &ch1Callbacks](ChannelCallbacks& cb) {
      ch1->Channel::setChannelCallbacks(cb);
      ch1Callbacks = &cb;
    });

  Registry::InjectFactory<ChannelFilterFactoryConfig> inject(cfg);
  ExtensionConfigList enabledChannelFilters;
  {
    auto* cfg = enabledChannelFilters.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::StringValue v;
    v.set_value("factory_config");
    cfg->mutable_typed_config()->PackFrom(v);
  }
  ExtensionConfigList filterConfigs;
  {
    auto* cfg = filterConfigs.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::StringValue v;
    v.set_value("filter_config");
    cfg->mutable_typed_config()->PackFrom(v);
  }

  channel_filter_manager_.reset(new ChannelFilterManager(enabledChannelFilters, context_));
  ASSERT_OK(channel_filter_manager_->configureFilters(filterConfigs));

  // 1) receive channel open
  EXPECT_CALL(*ch1, readChannelOpen)
    .WillOnce([&ch1Callbacks](wire::ChannelOpenMsg&& msg) {
      EXPECT_EQ(1u, *msg.sender_channel);
      EXPECT_EQ("session", msg.channel_type());
      return ch1Callbacks->sendMessageRemote(std::move(msg));
    });
  EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelOpenMsg,
                                            FIELD_EQ(sender_channel, channelId),
                                            FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _)))))
    .WillOnce(InvokeWithoutArgs([&ch1Callbacks] {
      EXPECT_EQ("session", ch1Callbacks->channelType());
    }));
  EXPECT_CALL(*transport_, forward(MSG(wire::ChannelOpenMsg,
                                       FIELD_EQ(sender_channel, channelId),
                                       FIELD(request, SUB_MSG(wire::SessionChannelOpenMsg, _))),
                                   _));

  // 2) receive channel data
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelDataMsg,
                                    FIELD_EQ(recipient_channel, channelId),
                                    FIELD(data, "hello world"_bytes))))
    .WillOnce([&ch1Callbacks](wire::Message&& msg) {
      return ch1Callbacks->sendMessageRemote(std::move(msg));
    });
  EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelDataMsg,
                                            FIELD_EQ(recipient_channel, 2u),
                                            FIELD(data, "hello world"_bytes))));
  EXPECT_CALL(*transport_, forward(MSG(wire::ChannelDataMsg,
                                       FIELD_EQ(recipient_channel, 2u),
                                       FIELD(data, "hello world"_bytes)),
                                   _));

  // 3) interrupt
  EXPECT_CALL(*transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg,
                                                       FIELD_EQ(recipient_channel, 1u))))
    .WillOnce(Return(0uz));

  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelCloseMsg,
                                    FIELD_EQ(recipient_channel, channelId))))
    .WillOnce([&ch1Callbacks](wire::Message&& msg) {
      return ch1Callbacks->sendMessageRemote(std::move(msg));
    });
  EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelCloseMsg,
                                            FIELD_EQ(recipient_channel, 2u))));
  EXPECT_CALL(*transport_, forward(MSG(wire::ChannelCloseMsg,
                                       FIELD_EQ(recipient_channel, 2u)),
                                   _));
  EXPECT_CALL(*ch1, Die);

  //

  ASSERT_OK(service_->startChannel(std::move(ch1),
                                   {
                                     .allocated_channel_id = channelId,
                                     .channel_open = wire::ChannelOpenMsg{
                                       .sender_channel = 1,
                                       .request = wire::SessionChannelOpenMsg{},
                                     },
                                   }));
  ASSERT_OK(channel_id_manager_.bindChannelID(channelId, PeerLocalID{
                                                           .channel_id = 2,
                                                           .local_peer = Upstream,
                                                         }));

  ASSERT_OK(service_->handleMessage(wire::ChannelDataMsg{
    .recipient_channel = channelId,
    .data = "hello world"_bytes,
  }));

  bool called{};
  auto cbHandle = ch1Callbacks->addInterruptCallback([&called](absl::Status err, TransportCallbacks&) {
    EXPECT_EQ(absl::InternalError("test error"), err);
    called = true;
  });
  channelFilterCallbacks->interruptChannel(absl::InternalError("test error"));
  EXPECT_TRUE(called);
  ASSERT_OK(service_->handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channelId,
  }));
}

TEST_F(UpstreamConnectionServiceTest, TestChannelWriteFilters) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  IN_SEQUENCE;

  auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
  auto filter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([&] {
      return std::move(factory);
    });

  auto ch1 = std::make_unique<testing::StrictMock<MockChannel>>();
  ChannelFilterCallbacks* channelFilterCallbacks{};
  ChannelCallbacks* ch1Callbacks{};
  auto channelId = *channel_id_manager_.allocateNewChannel(Peer::Downstream);

  EXPECT_CALL(*factory, createEmptyConfigProto)
    .WillOnce([] {
      return std::make_unique<Envoy::Protobuf::StringValue>();
    });
  EXPECT_CALL(*factory, createWriteFilter)
    .WillOnce([&](const google::protobuf::Message& config, ChannelFilterCallbacks& filter_callbacks) {
      EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
      EXPECT_EQ(static_cast<stream_id_t>(1), filter_callbacks.streamId());
      channelFilterCallbacks = &filter_callbacks;
      EXPECT_EQ(channelId, filter_callbacks.channelId());
      return std::move(filter);
    });
  EXPECT_CALL(*ch1, setChannelCallbacks)
    .WillOnce([ch1 = ch1.get(), &ch1Callbacks](ChannelCallbacks& cb) {
      ch1->Channel::setChannelCallbacks(cb);
      ch1Callbacks = &cb;
    });

  Registry::InjectFactory<ChannelFilterFactoryConfig> inject(cfg);

  ExtensionConfigList enabledChannelFilters;
  {
    auto* cfg = enabledChannelFilters.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::StringValue v;
    v.set_value("factory_config");
    cfg->mutable_typed_config()->PackFrom(v);
  }
  ExtensionConfigList filterConfigs;
  {
    auto* cfg = filterConfigs.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::StringValue v;
    v.set_value("filter_config");
    cfg->mutable_typed_config()->PackFrom(v);
  }

  channel_filter_manager_.reset(new ChannelFilterManager(enabledChannelFilters, context_));
  ASSERT_OK(channel_filter_manager_->configureFilters(filterConfigs));

  ASSERT_OK(channel_id_manager_.bindChannelID(channelId, PeerLocalID{
                                                           .channel_id = 1,
                                                           .local_peer = Downstream,
                                                         }));

  // 1) receive channel open confirmation
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelOpenConfirmationMsg,
                                    FIELD_EQ(recipient_channel, channelId),
                                    FIELD_EQ(sender_channel, channelId))))
    .WillOnce([&ch1Callbacks](wire::Message&& msg) {
      return ch1Callbacks->sendMessageRemote(std::move(msg));
    });
  EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelOpenConfirmationMsg,
                                            FIELD_EQ(sender_channel, channelId),
                                            FIELD_EQ(recipient_channel, 1u))))
    .WillOnce(InvokeWithoutArgs([&ch1Callbacks] {
      // the write filter won't have the channel type
      EXPECT_EQ(std::nullopt, ch1Callbacks->channelType());
    }));
  EXPECT_CALL(*transport_, forward(MSG(wire::ChannelOpenConfirmationMsg,
                                       FIELD_EQ(sender_channel, channelId),
                                       FIELD_EQ(recipient_channel, 1u)),
                                   _));

  // 2) receive channel data
  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelDataMsg,
                                    FIELD_EQ(recipient_channel, channelId),
                                    FIELD_EQ(data, "hello world"_bytes))))
    .WillOnce([&ch1Callbacks](wire::Message&& msg) {
      return ch1Callbacks->sendMessageRemote(std::move(msg));
    });
  EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelDataMsg,
                                            FIELD_EQ(recipient_channel, 1u),
                                            FIELD(data, "hello world"_bytes))));
  EXPECT_CALL(*transport_, forward(MSG(wire::ChannelDataMsg,
                                       FIELD_EQ(recipient_channel, 1u),
                                       FIELD_EQ(data, "hello world"_bytes)),
                                   _));

  // 3) interrupt
  EXPECT_CALL(*transport_, sendMessageToConnection(MSG(wire::ChannelCloseMsg,
                                                       FIELD_EQ(recipient_channel, 2u))))
    .WillOnce(Return(0uz));

  EXPECT_CALL(*ch1, readMessage(MSG(wire::ChannelCloseMsg,
                                    FIELD_EQ(recipient_channel, channelId))))
    .WillOnce([&ch1Callbacks](wire::Message&& msg) {
      return ch1Callbacks->sendMessageRemote(std::move(msg));
    });
  EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelCloseMsg,
                                            FIELD_EQ(recipient_channel, 1u))));
  EXPECT_CALL(*transport_, forward(MSG(wire::ChannelCloseMsg,
                                       FIELD_EQ(recipient_channel, 1u)),
                                   _));
  EXPECT_CALL(*ch1, Die);

  //

  ASSERT_OK(service_->startChannel(std::move(ch1), {.allocated_channel_id = channelId}));
  ASSERT_OK(service_->handleMessage(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = channelId,
    .sender_channel = 2,
  }));
  ASSERT_OK(service_->handleMessage(wire::ChannelDataMsg{
    .recipient_channel = channelId,
    .data = "hello world"_bytes,
  }));

  bool called{};
  auto cbHandle = ch1Callbacks->addInterruptCallback([&called](absl::Status err, TransportCallbacks&) {
    EXPECT_EQ(absl::InternalError("test error"), err);
    called = true;
  });
  ASSERT_TRUE(channelFilterCallbacks->interruptChannel(absl::InternalError("test error")));
  EXPECT_TRUE(called);

  // interruptChannel should return false if called a second time, since the channel is no longer
  // preemptible.
  // Order is important wrt receiving the ChannelClose message below. After receiving the close
  // message the channel will be destroyed and channelFilterCallbacks will point to garbage.
  ASSERT_FALSE(channelFilterCallbacks->interruptChannel(absl::InternalError("test error")));

  ASSERT_OK(service_->handleMessage(wire::ChannelCloseMsg{
    .recipient_channel = channelId,
  }));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec