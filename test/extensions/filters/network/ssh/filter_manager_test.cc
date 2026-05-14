
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_common.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "envoy/extensions/filters/network/generic_proxy/v3/generic_proxy.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

enum Direction {
  Read,
  Write
};

using on_channel_filter_created_fn_t = testing::StrictMock<testing::MockFunction<void(uint32_t, uint32_t, std::string, Direction)>>;
using on_channel_filter_destroyed_fn_t = testing::StrictMock<testing::MockFunction<void(uint32_t, uint32_t, std::string, Direction)>>;
using on_channel_filter_factory_created_fn_t = testing::StrictMock<testing::MockFunction<void(uint32_t)>>;
using on_channel_filter_factory_destroyed_fn_t = testing::StrictMock<testing::MockFunction<void(uint32_t)>>;
using on_message_forward_fn_t = testing::StrictMock<testing::MockFunction<void(uint32_t, uint32_t, std::string, Direction, const wire::Message&)>>;

static Envoy::OptRef<on_channel_filter_created_fn_t> on_channel_filter_created;
static Envoy::OptRef<on_channel_filter_destroyed_fn_t> on_channel_filter_destroyed;
static Envoy::OptRef<on_channel_filter_factory_created_fn_t> on_channel_filter_factory_created;
static Envoy::OptRef<on_channel_filter_factory_destroyed_fn_t> on_channel_filter_factory_destroyed;
static Envoy::OptRef<on_message_forward_fn_t> on_message_forward;

class TestChannelFilter : public ChannelFilter {
public:
  TestChannelFilter(uint32_t instance_num, uint32_t filter_instance_num, const std::string& name, Direction direction)
      : instance_num_(instance_num),
        filter_instance_num_(filter_instance_num),
        name_(name),
        direction_(direction) {
    on_channel_filter_created->Call(instance_num_, filter_instance_num_, name_, direction_);
  }
  ~TestChannelFilter() {
    on_channel_filter_destroyed->Call(instance_num_, filter_instance_num_, name_, direction_);
  }

  void onMessageForward(const wire::Message& msg) override {
    on_message_forward->Call(instance_num_, filter_instance_num_, name_, direction_, msg);
  }

private:
  const uint32_t instance_num_;
  const uint32_t filter_instance_num_;
  const std::string name_;
  const Direction direction_;
};

class TestChannelFilterFactory : public ChannelFilterFactory {
public:
  TestChannelFilterFactory(uint32_t instance_num)
      : instance_num_(instance_num) {
    on_channel_filter_factory_created->Call(instance_num_);
  }
  ~TestChannelFilterFactory() {
    on_channel_filter_factory_destroyed->Call(instance_num_);
  }

  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Protobuf::StringValue>();
  }

  Codec::ChannelFilterPtr createReadFilter(const google::protobuf::Message& config,
                                           Codec::ChannelFilterCallbacks& channel_callbacks) override {
    EXPECT_EQ(config.GetTypeName(), "google.protobuf.StringValue");
    (void)channel_callbacks;
    return std::make_unique<TestChannelFilter>(instance_num_,
                                               read_filter_instance_num_++,
                                               dynamic_cast<const Protobuf::StringValue&>(config).value(),
                                               Read);
  }

  Codec::ChannelFilterPtr createWriteFilter(const google::protobuf::Message& config,
                                            Codec::ChannelFilterCallbacks& channel_callbacks) override {
    EXPECT_EQ(config.GetTypeName(), "google.protobuf.StringValue");
    (void)channel_callbacks;
    return std::make_unique<TestChannelFilter>(instance_num_,
                                               write_filter_instance_num_++,
                                               dynamic_cast<const Protobuf::StringValue&>(config).value(),
                                               Write);
  }

private:
  const uint32_t instance_num_;
  uint32_t read_filter_instance_num_{};
  uint32_t write_filter_instance_num_{};
};

class TestChannelFilterFactoryConfig : public Codec::ChannelFilterFactoryConfig {
public:
  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<google::protobuf::Int32Value>();
  }

  std::string name() const override {
    return "test_filter";
  }

  Codec::ChannelFilterFactoryPtr createChannelFilterFactory(const google::protobuf::Message& config,
                                                            Envoy::Server::Configuration::ServerFactoryContext&) override {
    EXPECT_EQ(config.GetTypeName(), "google.protobuf.Int32Value");
    return std::make_unique<TestChannelFilterFactory>(instance_counter_++);
  }

private:
  std::atomic<uint32_t> instance_counter_;
};

REGISTER_FACTORY(TestChannelFilterFactoryConfig, ChannelFilterFactoryConfig);

// NOLINTBEGIN(readability-identifier-naming)
class ChannelFilterManagerIntegrationTest : public testing::Test,
                                            public SshIntegrationTest {
public:
  ChannelFilterManagerIntegrationTest()
      : SshIntegrationTest({"upstream1"}, Network::Address::IpVersion::v4) {
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      for (auto& listener : *bootstrap.mutable_static_resources()->mutable_listeners()) {
        if (listener.name() != "ssh") {
          continue;
        }
        auto* filter = listener.mutable_filter_chains(0)->mutable_filters(0);
        ASSERT(filter->name() == "generic_proxy"); // sanity check

        envoy::extensions::filters::network::generic_proxy::v3::GenericProxy genericProxyConfig;
        filter->typed_config().UnpackTo(&genericProxyConfig);

        pomerium::extensions::ssh::CodecConfig sshCodecConfig;
        genericProxyConfig.codec_config().typed_config().UnpackTo(&sshCodecConfig);

        auto* factoryConfig = sshCodecConfig.add_enabled_channel_filter_factories();
        factoryConfig->set_name("test_filter");
        factoryConfig->mutable_typed_config()->PackFrom(Protobuf::Int32Value{});

        genericProxyConfig.mutable_codec_config()->mutable_typed_config()->PackFrom(sshCodecConfig);

        filter->mutable_typed_config()->PackFrom(genericProxyConfig);
        break;
      }
    });
  }

  void SetUp() override {
    ASSERT_FALSE(on_channel_filter_created.has_value());
    ASSERT_FALSE(on_channel_filter_destroyed.has_value());
    ASSERT_FALSE(on_channel_filter_factory_created.has_value());
    ASSERT_FALSE(on_channel_filter_factory_destroyed.has_value());
    ASSERT_FALSE(on_message_forward.has_value());
    on_channel_filter_created.emplace(on_channel_filter_created_fn_);
    on_channel_filter_destroyed.emplace(on_channel_filter_destroyed_fn_);
    on_channel_filter_factory_created.emplace(on_channel_filter_factory_created_fn_);
    on_channel_filter_factory_destroyed.emplace(on_channel_filter_factory_destroyed_fn_);
    on_message_forward.emplace(on_message_forward_fn_);
    initialize();
  }

  void TearDown() override {
    EXPECT_TRUE(driver1_->closed());
    EXPECT_TRUE(driver2_->closed());
    cleanup();
    on_channel_filter_created.reset();
    on_channel_filter_destroyed.reset();
    on_channel_filter_factory_created.reset();
    on_channel_filter_factory_destroyed.reset();
    on_message_forward.reset();
  }

  void StartListeningForNewSshConnection() {
    ASSERT_TRUE(listenForSshConnection(SshFakeUpstreamHandlerOpts{
      .on_channel_open_request = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
        return [&](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
          return msg.visit(
            [&](wire::ChannelDataMsg& msg) {
              callbacks.sendMessageLocal(wire::ChannelDataMsg{
                .recipient_channel = callbacks.channelId(),
                .data = msg.data,
              });
              return absl::OkStatus();
            },
            [&](wire::ChannelCloseMsg&) {
              callbacks.sendMessageLocal(wire::ChannelCloseMsg{
                .recipient_channel = callbacks.channelId(),
              });
              return absl::OkStatus();
            },
            [&](auto&) {
              return absl::OkStatus();
            });
        };
      },
    }));
  }
  on_channel_filter_created_fn_t on_channel_filter_created_fn_;
  on_channel_filter_created_fn_t on_channel_filter_destroyed_fn_;
  on_channel_filter_factory_created_fn_t on_channel_filter_factory_created_fn_;
  on_channel_filter_factory_destroyed_fn_t on_channel_filter_factory_destroyed_fn_;
  on_message_forward_fn_t on_message_forward_fn_;

  std::shared_ptr<SshConnectionDriver> driver1_;
  std::shared_ptr<SshConnectionDriver> driver2_;
};
// NOLINTEND(readability-identifier-naming)

TEST_F(ChannelFilterManagerIntegrationTest, TestChannelFilterManagerPerConnection) {
  // Test that one ChannelFilterManager instance is created for each connection

  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  StartListeningForNewSshConnection();
  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());

  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(1));
  StartListeningForNewSshConnection();
  driver2_ = makeSshConnectionDriver();
  driver2_->connect();
  ASSERT_TRUE(driver2_->waitForKex());

  ASSERT_TRUE(driver1_->waitForUserAuth("user", "upstream1", [](pomerium::extensions::ssh::AllowResponse& allow) {
    ASSERT_TRUE(allow.has_upstream()); // sanity check
    auto* filterConfig = allow.mutable_upstream()->add_channel_filters();
    filterConfig->set_name("test_filter");
    Protobuf::StringValue cfg;
    cfg.set_value("driver1");
    filterConfig->mutable_typed_config()->PackFrom(cfg);
  }));
  ASSERT_TRUE(driver2_->waitForUserAuth("user", "upstream1", [](pomerium::extensions::ssh::AllowResponse& allow) {
    ASSERT_TRUE(allow.has_upstream()); // sanity check
    auto* filterConfig = allow.mutable_upstream()->add_channel_filters();
    filterConfig->set_name("test_filter");
    Protobuf::StringValue cfg;
    cfg.set_value("driver2");
    filterConfig->mutable_typed_config()->PackFrom(cfg);
  }));

  Tasks::Channel driver1Channel1;
  Tasks::Channel driver1Channel2;
  Tasks::Channel driver2Channel1;
  Tasks::Channel driver2Channel2;

  {
    IN_SEQUENCE;

    EXPECT_CALL(*on_channel_filter_created, Call(0, 0, "driver1", Read));
    EXPECT_CALL(*on_message_forward, Call(0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(*on_channel_filter_created, Call(0, 0, "driver1", Write));
    EXPECT_CALL(*on_message_forward, Call(0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, 1u))));
    EXPECT_CALL(*on_message_forward, Call(0, 0, "driver1", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 1"_bytes))));
    EXPECT_CALL(*on_message_forward, Call(0, 0, "driver1", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 1"_bytes))));
    ASSERT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::OpenSessionChannel>(1)
        .saveOutput(&driver1Channel1)
        .then(driver1_->createTask<Tasks::SendChannelData>("driver 1 channel 1")
                .then(driver1_->createTask<Tasks::WaitForChannelData>("driver 1 channel 1")))
        .start()));

    EXPECT_CALL(*on_channel_filter_created, Call(0, 1, "driver1", Read));
    EXPECT_CALL(*on_message_forward, Call(0, 1, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(*on_channel_filter_created, Call(0, 1, "driver1", Write));
    EXPECT_CALL(*on_message_forward, Call(0, 1, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, 2u))));
    EXPECT_CALL(*on_message_forward, Call(0, 1, "driver1", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 2"_bytes))));
    EXPECT_CALL(*on_message_forward, Call(0, 1, "driver1", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 2"_bytes))));
    ASSERT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::OpenSessionChannel>(2)
        .saveOutput(&driver1Channel2)
        .then(driver1_->createTask<Tasks::SendChannelData>("driver 1 channel 2")
                .then(driver1_->createTask<Tasks::WaitForChannelData>("driver 1 channel 2")))
        .start()));
  }

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_channel_filter_created_fn_, Call(1, 0, "driver2", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 0, "driver2", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(on_channel_filter_created_fn_, Call(1, 0, "driver2", Write));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 0, "driver2", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, 1u))));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 0, "driver2", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 1"_bytes))));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 0, "driver2", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 1"_bytes))));
    ASSERT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::OpenSessionChannel>(1)
        .saveOutput(&driver2Channel1)
        .then(driver2_->createTask<Tasks::SendChannelData>("driver 2 channel 1")
                .then(driver2_->createTask<Tasks::WaitForChannelData>("driver 2 channel 1")))
        .start()));

    EXPECT_CALL(on_channel_filter_created_fn_, Call(1, 1, "driver2", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 1, "driver2", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(on_channel_filter_created_fn_, Call(1, 1, "driver2", Write));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 1, "driver2", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, 2u))));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 1, "driver2", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 2"_bytes))));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 1, "driver2", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 2"_bytes))));
    ASSERT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::OpenSessionChannel>(2)
        .saveOutput(&driver2Channel2)
        .then(driver2_->createTask<Tasks::SendChannelData>("driver 2 channel 2")
                .then(driver2_->createTask<Tasks::WaitForChannelData>("driver 2 channel 2")))
        .start()));
  }

  // Close the channels

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_message_forward_fn_, Call(0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel1.remote_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(0, 0, "driver1", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel1.local_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(0, 0, "driver1", Write));
    ASSERT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver1Channel1)));

    EXPECT_CALL(on_message_forward_fn_, Call(0, 1, "driver1", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel2.remote_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(0, 1, "driver1", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(0, 1, "driver1", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel2.local_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(0, 1, "driver1", Write));
    ASSERT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver1Channel2)));
  }

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_message_forward_fn_, Call(1, 0, "driver2", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel1.remote_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(1, 0, "driver2", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 0, "driver2", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel1.local_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(1, 0, "driver2", Write));
    ASSERT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver2Channel1)));

    EXPECT_CALL(on_message_forward_fn_, Call(1, 1, "driver2", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel2.remote_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(1, 1, "driver2", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(1, 1, "driver2", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel2.local_id))));
    EXPECT_CALL(on_channel_filter_destroyed_fn_, Call(1, 1, "driver2", Write));
    ASSERT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver2Channel2)));
  }

  EXPECT_CALL(on_channel_filter_factory_destroyed_fn_, Call(0));
  ASSERT_TRUE(driver1_->disconnect());
  EXPECT_CALL(on_channel_filter_factory_destroyed_fn_, Call(1));
  ASSERT_TRUE(driver2_->disconnect());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec