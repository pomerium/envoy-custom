
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
  ChannelFilterManager mgr({}, server_factory_context_);
  EXPECT_EQ(0, mgr.numConfiguredFilters());

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

  ChannelFilterManager mgr({}, server_factory_context_);
  EXPECT_EQ(0, mgr.numConfiguredFilters());

  testing::StrictMock<MockChannelFilterCallbacks> cb;

  EXPECT_EQ(0, mgr.createReadFilters(cb).size());
  EXPECT_EQ(0, mgr.createWriteFilters(cb).size());
}

TEST_F(ChannelFilterTest, ChannelFilterManager_InvalidFactoryConfig) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  Registry::InjectFactory<ChannelFilterFactoryConfig> inject(cfg);

  ExtensionConfigList enabledChannelFilters;
  {
    auto* cfg = enabledChannelFilters.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::Int64Value v;
    v.set_value(1234);
    cfg->mutable_typed_config()->PackFrom(v);
  }

  EXPECT_THROW_WITH_REGEX(
    {
      ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);
    },
    Envoy::EnvoyException, "Unable to unpack as google\\.protobuf\\.StringValue.*");
}

TEST_F(ChannelFilterTest, ChannelFilterManager_FactoryNotFound) {
  ExtensionConfigList enabledChannelFilters;
  {
    auto* cfg = enabledChannelFilters.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::Int64Value v;
    v.set_value(1234);
    cfg->mutable_typed_config()->PackFrom(v);
  }

  EXPECT_THROW_WITH_REGEX(
    {
      ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);
    },
    Envoy::EnvoyException, "no registered channel filter factory found for name: test_channel_filter");
}

TEST_F(ChannelFilterTest, ChannelFilterManager_ConfigureFilters_NotFound) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([] {
      auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
      EXPECT_CALL(*factory, createEmptyConfigProto)
        .WillOnce([] { return std::make_unique<Envoy::Protobuf::StringValue>(); });
      return factory;
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
  ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);

  ExtensionConfigList filterConfigs;
  {
    auto* cfg = filterConfigs.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::StringValue v;
    v.set_value("filter_config");
    cfg->mutable_typed_config()->PackFrom(v);

    auto* cfg2 = filterConfigs.Add();
    cfg2->set_name("nonexistent");
  }
  EXPECT_EQ(absl::NotFoundError("channel filter not found: nonexistent"),
            mgr.configureFilters(filterConfigs));
  EXPECT_EQ(0, mgr.numConfiguredFilters());
}

TEST_F(ChannelFilterTest, ChannelFilterManager_ConfigureFilters_InvalidConfig) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([] {
      auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
      EXPECT_CALL(*factory, createEmptyConfigProto)
        .WillOnce([] {
          return std::make_unique<Envoy::Protobuf::StringValue>();
        });
      return factory;
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
  ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);

  ExtensionConfigList filterConfigs;
  {
    auto* cfg = filterConfigs.Add();
    cfg->set_name("test_channel_filter");
    Envoy::Protobuf::Int64Value v;
    v.set_value(1234);
    cfg->mutable_typed_config()->PackFrom(v);
  }
  EXPECT_THAT(mgr.configureFilters(filterConfigs).message(),
              HasSubstr("invalid channel filter config: Unable to unpack as google.protobuf.StringValue"));
  EXPECT_EQ(0, mgr.numConfiguredFilters());
}

TEST_F(ChannelFilterTest, ChannelFilterManager_NoChannelFiltersCreated) {
  testing::NiceMock<MockChannelFilterFactoryConfig> cfg;
  ON_CALL(cfg, createEmptyConfigProto).WillByDefault([] {
    return std::make_unique<Envoy::Protobuf::StringValue>();
  });
  ON_CALL(cfg, name).WillByDefault(Return("test_channel_filter"));

  EXPECT_CALL(cfg, createChannelFilterFactory)
    .WillOnce([](const google::protobuf::Message& config,
                 Envoy::Server::Configuration::ServerFactoryContext&) {
      EXPECT_EQ("factory_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
      auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
      EXPECT_CALL(*factory, createEmptyConfigProto)
        .WillOnce([] {
          return std::make_unique<Envoy::Protobuf::StringValue>();
        });
      EXPECT_CALL(*factory, createReadFilter)
        .WillOnce([](const google::protobuf::Message& config, ChannelFilterCallbacks&) {
          EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
          return nullptr;
        });
      EXPECT_CALL(*factory, createWriteFilter)
        .WillOnce([](const google::protobuf::Message& config, ChannelFilterCallbacks&) {
          EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
          return nullptr;
        });
      return factory;
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

  ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);

  testing::StrictMock<MockChannelFilterCallbacks> cb;

  EXPECT_OK(mgr.configureFilters(filterConfigs));
  EXPECT_EQ(1, mgr.numConfiguredFilters());

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
    .WillOnce([](const google::protobuf::Message& config,
                 Envoy::Server::Configuration::ServerFactoryContext&) {
      EXPECT_EQ("factory_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
      auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
      EXPECT_CALL(*factory, createEmptyConfigProto)
        .WillOnce([] {
          return std::make_unique<Envoy::Protobuf::StringValue>();
        });
      EXPECT_CALL(*factory, createReadFilter)
        .WillOnce([](const google::protobuf::Message& config, const ChannelFilterCallbacks& channel_callbacks) {
          EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
          EXPECT_EQ(1234, channel_callbacks.channelId());
          auto filter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
          EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelDataMsg, _)));
          return filter;
        });
      EXPECT_CALL(*factory, createWriteFilter)
        .WillOnce([](const google::protobuf::Message& config, const ChannelFilterCallbacks& channel_callbacks) {
          EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
          EXPECT_EQ(1234, channel_callbacks.channelId());
          auto filter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
          EXPECT_CALL(*filter, onMessageForward(MSG(wire::ChannelDataMsg, _)));
          return filter;
        });
      return factory;
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

  ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);

  testing::StrictMock<MockChannelFilterCallbacks> cb;
  EXPECT_CALL(cb, channelId)
    .Times(2)
    .WillRepeatedly(Return(1234));

  EXPECT_OK(mgr.configureFilters(filterConfigs));
  EXPECT_EQ(1, mgr.numConfiguredFilters());

  auto readFilters = mgr.createReadFilters(cb);
  auto writeFilters = mgr.createWriteFilters(cb);
  EXPECT_EQ(1, readFilters.size());
  EXPECT_EQ(1, writeFilters.size());

  wire::Message msg = wire::ChannelDataMsg{};
  readFilters[0]->onMessageForward(msg);
  writeFilters[0]->onMessageForward(msg);
}

TEST_F(ChannelFilterTest, ChannelFilterManager_MultipleFiltersConfigurationOrder) {
  std::vector<std::function<ProtobufTypes::MessagePtr()>> filterCfgTypes{
    [] { return std::make_unique<Envoy::Protobuf::StringValue>(); },
    [] { return std::make_unique<Envoy::Protobuf::Int32Value>(); },
    [] { return std::make_unique<Envoy::Protobuf::UInt32Value>(); },
    [] { return std::make_unique<Envoy::Protobuf::Int64Value>(); },
    [] { return std::make_unique<Envoy::Protobuf::DoubleValue>(); },
  };
  std::vector<std::unique_ptr<testing::NiceMock<MockChannelFilterFactoryConfig>>> filterCfgs;
  for (size_t i = 0; i < filterCfgTypes.size(); i++) {
    auto cfg = std::make_unique<decltype(filterCfgs)::value_type::element_type>();
    ON_CALL(*cfg, createEmptyConfigProto).WillByDefault([i, &filterCfgTypes] {
      return filterCfgTypes[i]();
    });
    ON_CALL(*cfg, name)
      .WillByDefault(Return(fmt::format("test_channel_filter_{}", i)));
    filterCfgs.push_back(std::move(cfg));
  }

  // This sequences checks that filters are created in the same order they are listed in the
  // configuration
  testing::Sequence factorySeq;
  testing::Sequence readFilterSeq;
  testing::Sequence writeFilterSeq;

  std::vector<std::unique_ptr<testing::StrictMock<MockChannelFilterFactory>>> tmpFactories;
  std::vector<std::unique_ptr<testing::StrictMock<MockChannelFilter>>> tmpReadFilters;
  std::vector<std::unique_ptr<testing::StrictMock<MockChannelFilter>>> tmpWriteFilters;
  for (size_t i = 0; i < filterCfgTypes.size(); i++) {
    auto factory = std::make_unique<testing::StrictMock<MockChannelFilterFactory>>();
    EXPECT_CALL(*factory, createEmptyConfigProto)
      .InSequence(factorySeq)
      .WillOnce([] {
        return std::make_unique<Envoy::Protobuf::StringValue>();
      });

    {
      auto readFilter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
      EXPECT_CALL(*readFilter, onMessageForward(MSG(wire::ChannelDataMsg, _)))
        .InSequence(readFilterSeq);
      tmpReadFilters.push_back(std::move(readFilter));
    }
    {
      auto writeFilter = std::make_unique<testing::StrictMock<MockChannelFilter>>();
      EXPECT_CALL(*writeFilter, onMessageForward(MSG(wire::ChannelDataMsg, _)))
        .InSequence(writeFilterSeq);
      tmpWriteFilters.push_back(std::move(writeFilter));
    }

    EXPECT_CALL(*factory, createReadFilter)
      .WillOnce([i, &tmpReadFilters](const google::protobuf::Message& config, const ChannelFilterCallbacks&) {
        EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
        return std::move(tmpReadFilters[i]);
      });
    EXPECT_CALL(*factory, createWriteFilter)
      .WillOnce([i, &tmpWriteFilters](const google::protobuf::Message& config, const ChannelFilterCallbacks&) {
        EXPECT_EQ("filter_config", dynamic_cast<const Envoy::Protobuf::StringValue&>(config).value());
        return std::move(tmpWriteFilters[i]);
      });

    tmpFactories.push_back(std::move(factory));
  }

  // Also check that the filter factories are created in order. Calls in this sequence may be
  // interleaved with calls in the above sequence, but the relative order of each will be enforced.
  testing::Sequence factoryConfigSeq;
  for (size_t i = 0; i < filterCfgTypes.size(); i++) {
    EXPECT_CALL(*filterCfgs[i], createChannelFilterFactory)
      .InSequence(factoryConfigSeq)
      .WillOnce([i, &tmpFactories](const google::protobuf::Message&,
                                   Envoy::Server::Configuration::ServerFactoryContext&) {
        return std::move(tmpFactories[i]);
      });
  }

  std::vector<std::unique_ptr<Registry::InjectFactory<ChannelFilterFactoryConfig>>> inject;
  for (auto& filterCfg : filterCfgs) {
    inject.push_back(std::make_unique<Registry::InjectFactory<ChannelFilterFactoryConfig>>(*filterCfg));
  }

  ExtensionConfigList enabledChannelFilters;
  ExtensionConfigList filterConfigs;
  for (size_t i = 0; i < filterCfgTypes.size(); i++) {
    {
      auto* cfg = enabledChannelFilters.Add();
      cfg->set_name(fmt::format("test_channel_filter_{}", i));
      auto msgPtr = filterCfgTypes[i]();
      cfg->mutable_typed_config()->PackFrom(*msgPtr);
    }

    {
      auto* cfg = filterConfigs.Add();
      cfg->set_name(fmt::format("test_channel_filter_{}", i));
      // filter type is always string here, these can have duplicate types
      Envoy::Protobuf::StringValue v;
      v.set_value("filter_config");
      cfg->mutable_typed_config()->PackFrom(v);
    }
  }

  ChannelFilterManager mgr(enabledChannelFilters, server_factory_context_);

  testing::StrictMock<MockChannelFilterCallbacks> cb;
  EXPECT_CALL(cb, channelId)
    .Times(AnyNumber())
    .WillRepeatedly(Return(1234));

  EXPECT_OK(mgr.configureFilters(filterConfigs));
  EXPECT_EQ(filterCfgTypes.size(), mgr.numConfiguredFilters());

  auto readFilters = mgr.createReadFilters(cb);
  auto writeFilters = mgr.createWriteFilters(cb);
  EXPECT_EQ(filterCfgTypes.size(), readFilters.size());
  EXPECT_EQ(filterCfgTypes.size(), writeFilters.size());

  // order of filters returned by create{Read|Write}Filters should match the configuration order,
  // so the order of onMessageForward calls should match readFilterSeq/writeFilterSeq
  wire::Message msg{wire::ChannelDataMsg{}};
  for (auto& rf : readFilters) {
    rf->onMessageForward(msg);
  }
  for (auto& wf : writeFilters) {
    wf->onMessageForward(msg);
  }
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec