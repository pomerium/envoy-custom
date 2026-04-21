
#include "source/extensions/filters/network/ssh/channel_filter_config.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/test_common.h"
#include "test/test_common/registry.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class ChannelFilterTest : public testing::Test {
public:
  void SetUp() override {
  }
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> server_factory_context_;
};

TEST_F(ChannelFilterTest, ChannelFilterManager_NoFilters) {
  ChannelFilterManager mgr(server_factory_context_, {});
  EXPECT_FALSE(mgr.hasFilters());

  testing::StrictMock<MockChannelFilterCallbacks> cb;

  EXPECT_EQ(0, mgr.createReadFilters(cb).size());
  EXPECT_EQ(0, mgr.createWriteFilters(cb).size());
}

TEST_F(ChannelFilterTest, ChannelFilterManager_NoEnabledFilters) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  Registry::InjectFactory<ChannelFilterFactoryConfig> inject(cfg);

  ChannelFilterManager mgr(server_factory_context_, {});
  EXPECT_FALSE(mgr.hasFilters());

  testing::StrictMock<MockChannelFilterCallbacks> cb;

  EXPECT_EQ(0, mgr.createReadFilters(cb).size());
  EXPECT_EQ(0, mgr.createWriteFilters(cb).size());
}

TEST_F(ChannelFilterTest, ChannelFilterManager_NoChannelFiltersCreated) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([] {
      auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
      EXPECT_CALL(*factory, createReadFilter)
        .WillOnce(Return(nullptr));
      EXPECT_CALL(*factory, createWriteFilter)
        .WillOnce(Return(nullptr));
      return factory;
    });
  Registry::InjectFactory<ChannelFilterFactoryConfig> inject(cfg);

  ChannelFilterManager mgr(server_factory_context_, {cfg.name()});
  EXPECT_TRUE(mgr.hasFilters());

  testing::StrictMock<MockChannelFilterCallbacks> cb;

  EXPECT_EQ(0, mgr.createReadFilters(cb).size());
  EXPECT_EQ(0, mgr.createWriteFilters(cb).size());
}

TEST_F(ChannelFilterTest, ChannelFilterManager_FiltersCreated) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([] {
      auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
      EXPECT_CALL(*factory, createReadFilter)
        .WillOnce([](const ChannelReadOnlyCallbacks& channel_callbacks) {
          EXPECT_EQ(1234, channel_callbacks.channelId());
          auto filter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
          EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelDataMsg, _)));
          return filter;
        });
      EXPECT_CALL(*factory, createWriteFilter)
        .WillOnce([](const ChannelReadOnlyCallbacks& channel_callbacks) {
          EXPECT_EQ(1234, channel_callbacks.channelId());
          auto filter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
          EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelDataMsg, _)));
          return filter;
        });
      return factory;
    });
  Registry::InjectFactory<ChannelFilterFactoryConfig> inject(cfg);

  ChannelFilterManager mgr(server_factory_context_, {cfg.name()});
  EXPECT_TRUE(mgr.hasFilters());

  testing::StrictMock<MockChannelFilterCallbacks> cb;
  EXPECT_CALL(cb, channelId)
    .Times(2)
    .WillRepeatedly(Return(1234));

  auto readFilters = mgr.createReadFilters(cb);
  auto writeFilters = mgr.createWriteFilters(cb);
  EXPECT_EQ(1, readFilters.size());
  EXPECT_EQ(1, writeFilters.size());

  wire::Message msg = wire::ChannelDataMsg{};
  readFilters[0]->onMessageForward(msg);
  writeFilters[0]->onMessageForward(msg);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec