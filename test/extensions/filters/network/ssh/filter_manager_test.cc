
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/ssh_integration_common.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/test_common.h"
#include "test/test_common/registry.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "envoy/extensions/filters/network/generic_proxy/v3/generic_proxy.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

enum Direction {
  Read,
  Write
};

class TestChannelFilter;

using on_channel_filter_created_fn_t = testing::StrictMock<testing::MockFunction<void(TestChannelFilter*, uint32_t, uint32_t, std::string, Direction)>>;
using on_channel_filter_factory_created_fn_t = testing::StrictMock<testing::MockFunction<void(uint32_t)>>;
using on_message_forward_fn_t = testing::StrictMock<testing::MockFunction<absl::Status(TestChannelFilter*, uint32_t, uint32_t, std::string, Direction, const wire::Message&)>>;

static Envoy::OptRef<on_channel_filter_created_fn_t> on_channel_filter_created;
static Envoy::OptRef<on_channel_filter_factory_created_fn_t> on_channel_filter_factory_created;
static Envoy::OptRef<on_message_forward_fn_t> on_message_forward;

class TestChannelFilter : public ChannelFilter {
public:
  TestChannelFilter(Codec::ChannelFilterCallbacks& callbacks, uint32_t instance_num, uint32_t filter_instance_num, const std::string& name, Direction direction)
      : callbacks_(callbacks),
        instance_num_(instance_num),
        filter_instance_num_(filter_instance_num),
        name_(name),
        direction_(direction) {
    on_channel_filter_created->Call(this, instance_num_, filter_instance_num_, name_, direction_);
  }

  absl::Status onMessageForward(const wire::Message& msg) override {
    return on_message_forward->Call(this, instance_num_, filter_instance_num_, name_, direction_, msg);
  }

  Codec::ChannelFilterCallbacks& Callbacks() const { // NOLINT
    return callbacks_;
  }

private:
  Codec::ChannelFilterCallbacks& callbacks_;
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

  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Protobuf::StringValue>();
  }

  absl::StatusOr<Codec::ChannelFilterPtr> createReadFilter(const google::protobuf::Message& config,
                                                           Codec::ChannelFilterCallbacks& channel_callbacks) override {
    EXPECT_EQ(config.GetTypeName(), "google.protobuf.StringValue");
    return std::make_unique<TestChannelFilter>(channel_callbacks,
                                               instance_num_,
                                               read_filter_instance_num_++,
                                               dynamic_cast<const Protobuf::StringValue&>(config).value(),
                                               Read);
  }

  absl::StatusOr<Codec::ChannelFilterPtr> createWriteFilter(const google::protobuf::Message& config,
                                                            Codec::ChannelFilterCallbacks& channel_callbacks) override {
    EXPECT_EQ(config.GetTypeName(), "google.protobuf.StringValue");
    return std::make_unique<TestChannelFilter>(channel_callbacks,
                                               instance_num_,
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

  ~ChannelFilterManagerIntegrationTest() {
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(on_channel_filter_created.ptr()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(on_channel_filter_factory_created.ptr()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(on_message_forward.ptr()));
    on_channel_filter_created.reset();
    on_channel_filter_factory_created.reset();
    on_message_forward.reset();
  }

  void SetUp() override {
    inject_ = std::make_unique<Registry::InjectFactory<ChannelFilterFactoryConfig>>(channel_filter_factory_config_);

    ASSERT_FALSE(on_channel_filter_created.has_value());
    ASSERT_FALSE(on_channel_filter_factory_created.has_value());
    ASSERT_FALSE(on_message_forward.has_value());
    on_channel_filter_created.emplace(on_channel_filter_created_fn_);
    on_channel_filter_factory_created.emplace(on_channel_filter_factory_created_fn_);
    on_message_forward.emplace(on_message_forward_fn_);
    initialize();
  }

  void TearDown() override {
    if (driver1_ != nullptr) {
      EXPECT_TRUE(driver1_->closed());
    }
    if (driver2_ != nullptr) {
      EXPECT_TRUE(driver2_->closed());
    }
    cleanup();
  }

  SshFakeUpstreamHandlerOpts NewDefaultFakeUpstreamHandlerOpts() {
    ASSERT_IS_MAIN_OR_TEST_THREAD();

    auto onChannelOpenRequest = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
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
    };
    auto onChannelCreated = [this](uint32_t id) -> OnChannelDestroyedFunc {
      auto destroyNotification = std::make_shared<absl::Notification>();
      absl::MutexLock lock(upstream_channels_mu_);
      upstream_channels_.push_back({
        .upstream_id = id,
        .on_channel_destroyed = destroyNotification,
      });
      return [destroyNotification] {
        destroyNotification->Notify();
      };
    };

    // note: clang-format breaks when trying to format the lambdas inline here, so they are defined
    // separately
    return SshFakeUpstreamHandlerOpts{
      .on_channel_open_request = onChannelOpenRequest,
      .on_channel_created = onChannelCreated,
    };
  }
  void StartListeningForNewSshConnection() {
    ASSERT_TRUE(listenForSshConnection(NewDefaultFakeUpstreamHandlerOpts()));
  }

  AssertionResult WaitForDriver1Authenticated() {
    return driver1_->waitForUserAuth("user", "upstream1", [](pomerium::extensions::ssh::AllowResponse& allow) {
      ASSERT_TRUE(allow.has_upstream()); // sanity check
      auto* filterConfig = allow.mutable_upstream()->add_channel_filters();
      filterConfig->set_name("test_filter");
      Protobuf::StringValue cfg;
      cfg.set_value("driver1");
      ASSERT_TRUE(filterConfig->mutable_typed_config()->PackFrom(cfg));
    });
  }

  AssertionResult WaitForDriver2Authenticated() {
    return driver2_->waitForUserAuth("user", "upstream1", [](pomerium::extensions::ssh::AllowResponse& allow) {
      ASSERT_TRUE(allow.has_upstream()); // sanity check
      auto* filterConfig = allow.mutable_upstream()->add_channel_filters();
      filterConfig->set_name("test_filter");
      Protobuf::StringValue cfg;
      cfg.set_value("driver2");
      ASSERT_TRUE(filterConfig->mutable_typed_config()->PackFrom(cfg));
    });
  }

  struct UpstreamChannelInfo {
    uint32_t upstream_id; // upstream peer-relative id
    std::shared_ptr<absl::Notification> on_channel_destroyed;
  };

  absl::StatusOr<UpstreamChannelInfo> WaitForNextUpstreamChannel(absl::Duration timeout = absl::Seconds(1)) {
    auto nextIndex = upstream_channels_next_wait_index_.fetch_add(1);
    auto input = std::pair{&upstream_channels_, nextIndex};
    absl::Condition cond(+[](decltype(input)* in) { return in->first->size() >= (in->second + 1); }, &input);
    auto ok = upstream_channels_mu_.LockWhenWithTimeout(cond, timeout);
    if (!ok) {
      upstream_channels_mu_.unlock();
      return absl::InternalError("timed out waiting for next upstream channel open");
    }
    auto info = upstream_channels_[nextIndex];
    upstream_channels_mu_.unlock();
    return info;
  }

  TestChannelFilterFactoryConfig channel_filter_factory_config_;
  std::unique_ptr<Registry::InjectFactory<ChannelFilterFactoryConfig>> inject_;

  on_channel_filter_created_fn_t on_channel_filter_created_fn_;
  on_channel_filter_factory_created_fn_t on_channel_filter_factory_created_fn_;
  on_message_forward_fn_t on_message_forward_fn_;

  std::shared_ptr<SshConnectionDriver> driver1_;
  std::shared_ptr<SshConnectionDriver> driver2_;

  std::atomic<size_t> upstream_channels_next_wait_index_{0};
  absl::Mutex upstream_channels_mu_;
  std::vector<UpstreamChannelInfo> upstream_channels_ ABSL_GUARDED_BY(upstream_channels_mu_);
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

  ASSERT_TRUE(WaitForDriver1Authenticated());
  ASSERT_TRUE(WaitForDriver2Authenticated());

  Tasks::Channel driver1Channel1;
  Tasks::Channel driver1Channel2;
  Tasks::Channel driver2Channel1;
  Tasks::Channel driver2Channel2;

  // hard-coding these but if the configuration ever changes the asserts should fail
  uint32_t channel1InternalId = 100;
  uint32_t channel2InternalId = 101;

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, channel1InternalId))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 1"_bytes))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 1"_bytes))));
    EXPECT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::OpenSessionChannel>(1)
        .saveOutput(&driver1Channel1)
        .then(driver1_->createTask<Tasks::SendChannelData>("driver 1 channel 1")
                .then(driver1_->createTask<Tasks::WaitForChannelData>("driver 1 channel 1")))
        .start()));

    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 1, "driver1", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 1, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 1, "driver1", Write));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 1, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, channel2InternalId))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 1, "driver1", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 2"_bytes))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 1, "driver1", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 1 channel 2"_bytes))));
    EXPECT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::OpenSessionChannel>(2)
        .saveOutput(&driver1Channel2)
        .then(driver1_->createTask<Tasks::SendChannelData>("driver 1 channel 2")
                .then(driver1_->createTask<Tasks::WaitForChannelData>("driver 1 channel 2")))
        .start()));

    // sanity check
    ASSERT_EQ(driver1Channel1.remote_id, channel1InternalId);
    ASSERT_EQ(driver1Channel2.remote_id, channel2InternalId);
  }

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 1, 0, "driver2", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 0, "driver2", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 1, 0, "driver2", Write));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 0, "driver2", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, channel1InternalId))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 0, "driver2", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 1"_bytes))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 0, "driver2", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 1"_bytes))));
    EXPECT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::OpenSessionChannel>(1)
        .saveOutput(&driver2Channel1)
        .then(driver2_->createTask<Tasks::SendChannelData>("driver 2 channel 1")
                .then(driver2_->createTask<Tasks::WaitForChannelData>("driver 2 channel 1")))
        .start()));

    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 1, 1, "driver2", Read));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 1, "driver2", Read, MSG(wire::ChannelOpenMsg, _)));
    EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 1, 1, "driver2", Write));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 1, "driver2", Write, MSG(wire::ChannelOpenConfirmationMsg, FIELD_EQ(recipient_channel, channel2InternalId))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 1, "driver2", Read, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 2"_bytes))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 1, "driver2", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "driver 2 channel 2"_bytes))));
    EXPECT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::OpenSessionChannel>(2)
        .saveOutput(&driver2Channel2)
        .then(driver2_->createTask<Tasks::SendChannelData>("driver 2 channel 2")
                .then(driver2_->createTask<Tasks::WaitForChannelData>("driver 2 channel 2")))
        .start()));

    // sanity check
    ASSERT_EQ(driver2Channel1.remote_id, channel1InternalId);
    ASSERT_EQ(driver2Channel2.remote_id, channel2InternalId);
  }

  // Close the channels

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel1.remote_id))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel1.remote_id))));
    ASSERT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver1Channel1)));

    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 1, "driver1", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel2.remote_id))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 1, "driver1", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver1Channel2.remote_id))));
    ASSERT_TRUE(driver1_->wait(
      driver1_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver1Channel2)));
  }

  {
    IN_SEQUENCE;

    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 0, "driver2", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel1.remote_id))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 0, "driver2", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel1.remote_id))));
    ASSERT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver2Channel1)));

    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 1, "driver2", Read, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel2.remote_id))));
    EXPECT_CALL(on_message_forward_fn_, Call(_, 1, 1, "driver2", Write, MSG(wire::ChannelCloseMsg, FIELD_EQ(recipient_channel, driver2Channel2.remote_id))));
    ASSERT_TRUE(driver2_->wait(
      driver2_->createTask<Tasks::SendChannelCloseAndWait>()
        .start(driver2Channel2)));
  }

  ASSERT_TRUE(driver1_->disconnect());
  ASSERT_TRUE(driver2_->disconnect());
}

TEST_F(ChannelFilterManagerIntegrationTest, TestReadFilterInterruptInChannelOpen) {
  // Test interrupting the read filter while it is handling an outgoing ChannelOpen message

  // In this scenario, no messages should be forwarded after ChannelOpen. The downstream will send
  // ChannelOpenFailure locally, then the upstream will send ChannelClose locally via a
  // ForceCloseChannel created after receiving the upstream ChannelOpenConfirmation.

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)))
    .WillOnce([](TestChannelFilter* self, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      auto ok = self->Callbacks().interruptChannel(absl::InternalError("test error"));
      EXPECT_TRUE(ok);
      return absl::OkStatus();
    });
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  StartListeningForNewSshConnection();
  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1, Tasks::ExpectSuccess(false))
      .start()));

  // Wait until the upstream is able to process the ChannelOpen, then receives the ChannelClose
  // and is destroyed
  auto upstreamChannel = WaitForNextUpstreamChannel();
  ASSERT_OK(upstreamChannel);
  upstreamChannel.value().on_channel_destroyed->WaitForNotificationWithTimeout(absl::Seconds(1));

  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterManagerIntegrationTest, TestReadFilterInterruptBeforeChannelOpenConfirmation) {
  // Test interrupting the read filter after forwarding ChannelOpen, but before the write filter
  // receives ChannelOpenConfirmation

  // The message sequence in this scenario should be the same as above, but the channel is
  // interrupted in a future event loop cycle instead of during readChannelOpen. The ChannelOpen
  // message is sent to the upstream in both cases.

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  TestChannelFilter* readFilter{};
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read))
    .WillOnce([&readFilter](TestChannelFilter* read_filter, uint32_t, uint32_t, std::string, Direction) {
      readFilter = read_filter;
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [&readFilter](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    ASSERT(readFilter != nullptr);
    absl::Notification notify;
    ASSERT(!readFilter->Callbacks().connectionDispatcher().isThreadSafe());
    readFilter->Callbacks().connectionDispatcher().post([&notify, &readFilter] {
      EXPECT_TRUE(readFilter->Callbacks().interruptChannel(absl::InternalError("test error")));
      notify.Notify();
    });
    EXPECT_TRUE(notify.WaitForNotificationWithTimeout(absl::Seconds(1)));
    return [&](wire::ChannelMessage&& msg, ChannelCallbacks&) -> absl::Status {
      // The only message we should ever get after this is ChannelClose (and Disconnect, but that
      // is handled separately)
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      return absl::OkStatus();
    };
  };
  ASSERT_TRUE(listenForSshConnection(std::move(opts)));
  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1, Tasks::ExpectSuccess(false))
      .start()));

  auto upstreamChannel = WaitForNextUpstreamChannel();
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(absl::Seconds(1));
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterManagerIntegrationTest, TestReadFilterInterruptDuringChannelOpenConfirmation) {
  // Test interrupting the read filter while the write filter is handling the ChannelOpenConfirmation
  // and is about to forward it
}

TEST_F(ChannelFilterManagerIntegrationTest, TestWriteFilterInterruptDuringChannelOpenConfirmation) {
  // Test interrupting the write filter while handling the ChannelOpenConfirmation
  // and is about to forward it
}

TEST_F(ChannelFilterManagerIntegrationTest, TestWriteFilterPauseDuringChannelOpenConfirmation) {
  // Test pausing the write filter while handling the ChannelOpenConfirmation. It should queue
  // the message instead of forwarding it, until reads are re-enabled.
}

TEST_F(ChannelFilterManagerIntegrationTest, TestWriteFilterPauseDuringChannelOpenConfirmationThenInterruptReadFilter) {
  // Test interrupting the read filter while the ChannelOpenConfirmation is queued because the write
  // filter paused the connection before forwarding the message
}

TEST_F(ChannelFilterManagerIntegrationTest, TestWriteFilterPauseDuringChannelOpenConfirmationThenInterruptWriteFilter) {
  // Test interrupting the write filter while the ChannelOpenConfirmation is queued because the write
  // filter paused the connection before forwarding the message
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec