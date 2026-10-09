
#include "source/extensions/filters/network/ssh/channel_filter.h"
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

  void TakeReadDisableHandle(ReadDisableHandlePtr handle) { // NOLINT
    owned_handles_.push_back(std::move(handle));
  }

private:
  Codec::ChannelFilterCallbacks& callbacks_;
  const uint32_t instance_num_;
  const uint32_t filter_instance_num_;
  const std::string name_;
  const Direction direction_;
  std::vector<ReadDisableHandlePtr> owned_handles_;
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
      if (!driver1_->closed()) {
        driver1_->close();
      }
    }
    if (driver2_ != nullptr) {
      EXPECT_TRUE(driver2_->closed());
      if (!driver2_->closed()) {
        driver2_->close();
      }
    }
    cleanup();
  }

  virtual SshFakeUpstreamHandlerOpts NewDefaultFakeUpstreamHandlerOpts() {
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
    auto onChannelCreated = [this](uint32_t id, Envoy::Event::Dispatcher& dispatcher, ChannelCallbacks& callbacks) -> OnChannelDestroyedFunc {
      auto destroyNotification = std::make_shared<absl::Notification>();
      absl::MutexLock lock(upstream_channels_mu_);
      upstream_channels_.push_back({
        .upstream_id = id,
        .on_channel_destroyed = destroyNotification,
        .dispatcher = dispatcher,
        .channel_callbacks = callbacks,
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
  AssertionResult StartListeningForNewSshConnection() {
    return listenForSshConnection(NewDefaultFakeUpstreamHandlerOpts());
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
    Envoy::Event::Dispatcher& dispatcher;
    ChannelCallbacks& channel_callbacks;
  };

  absl::StatusOr<UpstreamChannelInfo> WaitForNextUpstreamChannel(absl::Duration timeout) {
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
  ASSERT_TRUE(StartListeningForNewSshConnection());
  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());

  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(1));
  ASSERT_TRUE(StartListeningForNewSshConnection());
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

class ChannelFilterInterruptIntegrationTest : public ChannelFilterManagerIntegrationTest {
public:
  ChannelFilterInterruptIntegrationTest() = default;

  SshFakeUpstreamHandlerOpts NewDefaultFakeUpstreamHandlerOpts() override {
    auto opts = ChannelFilterManagerIntegrationTest::NewDefaultFakeUpstreamHandlerOpts();
    opts.should_accept_channel = [this](uint32_t) {
      return upstream_accepts_channels_;
    };
    return opts;
  }

  bool upstream_accepts_channels_{true};
};

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadFilterInterruptInChannelOpen) {
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

  ASSERT_TRUE(StartListeningForNewSshConnection());
  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1, Tasks::ExpectSuccess(false))
      .start()));

  // Wait until the upstream is able to process the ChannelOpen, then receives the ChannelClose
  // and is destroyed
  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel.value().on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);

  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadFilterInterruptBeforeChannelOpenConfirmation) {
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
    EXPECT_TRUE(notify.WaitForNotificationWithTimeout(default_timeout_));
    return [&](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      // The only message we should ever get after this is ChannelClose
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
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

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadFilterInterruptBeforeChannelOpenFailure) {
  // Test interrupting the read filter after forwarding ChannelOpen, but before the write filter
  // receives ChannelOpenFailure

  upstream_accepts_channels_ = false;

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
    EXPECT_TRUE(notify.WaitForNotificationWithTimeout(default_timeout_));
    return [&](wire::ChannelMessage&& msg, ChannelCallbacks&) -> absl::Status {
      // No messages should be received by the upstream after it sends ChannelOpenFailure
      ADD_FAILURE() << fmt::format("unexpected message received: {}", msg.msg_type());
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

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadFilterInterruptDuringChannelOpenConfirmation) {
  // Test interrupting the read filter while the write filter is handling the
  // ChannelOpenConfirmation and is about to forward it

  // In this scenario the downstream should receive a ChannelOpenFailure, then transition to
  // preempted-closed and the ChannelOpenConfirmation should subsequently be dropped. The upstream
  // will be sent a ChannelClose internally and its reply should also be dropped, but not via
  // ForceCloseChannel because a PassthroughChannel has already been created

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  TestChannelFilter* readFilter{};
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read))
    .WillOnce([&readFilter](TestChannelFilter* read_filter, uint32_t, uint32_t, std::string, Direction) {
      readFilter = read_filter;
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([this, &readFilter](TestChannelFilter*, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      testing::MockFunction<void()> check;
      EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)));
      EXPECT_CALL(check, Call());
      EXPECT_TRUE(readFilter->Callbacks().interruptChannel(absl::InternalError("test error")));
      check.Call();
      return absl::OkStatus();
    });

  // Because the upstream channel is a PassthroughChannel, it will attempt to forward the close
  // message, but it should be dropped.
  absl::Notification done;
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)))
    .WillOnce(InvokeWithoutArgs([&done] {
      done.Notify();
      return absl::OkStatus();
    }));

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      // note this is the fake upstream (i.e. the upstream ssh server), which is implemented as a
      // one-sided transport. the local peer is the envoy upstream, and there is no remote peer
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
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

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(done.WaitForNotificationWithTimeout(default_timeout_));
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadFilterInterruptDuringChannelOpenFailure) {
  // Test interrupting the read filter while the write filter is handling the ChannelOpenFailure
  // and is about to forward it

  // In this scenario the downstream should receive a ChannelOpenFailure, then transition to
  // preempted-closed and the ChannelOpenFailure should subsequently be dropped. The upstream must
  // not be sent a ChannelClose internally, as would be the case if a ChannelOpenConfirmation were
  // received, because the channel never opened.

  upstream_accepts_channels_ = false;

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  TestChannelFilter* readFilter{};
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read))
    .WillOnce([&readFilter](TestChannelFilter* read_filter, uint32_t, uint32_t, std::string, Direction) {
      readFilter = read_filter;
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenFailureMsg, _)))
    .WillOnce([&readFilter](TestChannelFilter*, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      EXPECT_TRUE(readFilter->Callbacks().interruptChannel(absl::InternalError("test error")));
      return absl::OkStatus();
    });

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [](wire::ChannelMessage&& msg, ChannelCallbacks&) -> absl::Status {
      // No messages should be received by the upstream after it sends ChannelOpenFailure
      ADD_FAILURE() << fmt::format("unexpected message received: {}", msg.msg_type());
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

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestWriteFilterInterruptDuringChannelOpenConfirmation) {
  // Test interrupting the write filter while handling the ChannelOpenConfirmation
  // and is about to forward it

  // In this scenario the upstream should immediately be sent a ChannelClose, and the
  // ChannelOpenConfirmation should be forwarded to the downstream. The upstream will then reply
  // with a ChannelClose, forwarding it to the downstream. Because the downstream doesn't know that
  // internally we have sent the upstream a ChannelClose for (what it thinks to be) a valid open
  // channel, any messages sent by the downstream after the upstream is sent the ChannelClose should
  // be dropped.

  testing::Sequence s1;
  testing::Sequence s2;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0))
    .InSequence(s1, s2); /*1*/
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read))
    .InSequence(s1, s2); /*2*/
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)))
    .InSequence(s1, s2); /*3*/
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write))
    .InSequence(s1, s2); /*4*/
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .InSequence(s1, s2) /*5*/
    .WillOnce([](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      EXPECT_TRUE(write_filter->Callbacks().interruptChannel(absl::InternalError("test error")));
      return absl::OkStatus();
    });

  // These next two calls can happen in either order based on scheduling
  // The sequence DAG looks like this
  //                +-6a-+
  // 1--2--3--4--5--|    |--7
  //                +-6b-+
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)))
    .InSequence(s1);                                                                                /*6a*/
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelDataMsg, _))) // will be dropped
    .InSequence(s2);                                                                                /*6b*/

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _))) // will be dropped
    .InSequence(s1, s2);                                                                             /*7*/

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
      return absl::OkStatus();
    };
  };
  ASSERT_TRUE(listenForSshConnection(std::move(opts)));

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1)
      .then(driver1_->createTask<Tasks::SendChannelData>("test") // will be dropped
              .then(driver1_->createTask<Tasks::WaitForChannelCloseByPeer>()))
      .start()));

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestWriteFilterPauseDuringChannelOpenConfirmation) {
  // Test pausing the write filter while handling the ChannelOpenConfirmation. It should queue
  // the message instead of forwarding it, until reads are re-enabled.

  ReadDisableHandlePtr upstreamReadDisableHandle; // not owned by test thread
  Envoy::Event::TimerPtr timer1;                  // not owned by test thread
  Envoy::Event::TimerPtr timer2;                  // not owned by test thread
  std::optional<UpstreamChannelInfo> upstreamChannel;
  testing::MockFunction<void()> readEnable;
  testing::MockFunction<void()> clientChannelOpened;

  testing::Sequence s1;
  testing::Sequence s2;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0))
    .InSequence(s1, s2);
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read))
    .InSequence(s1, s2);
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)))
    .InSequence(s1, s2);
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write))
    .InSequence(s1, s2);

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .InSequence(s1, s2)
    .WillOnce([&upstreamReadDisableHandle, &upstreamChannel, &timer1, &timer2, &readEnable, this](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      upstreamReadDisableHandle = write_filter->Callbacks().connectionReadDisable();

      timer1 = write_filter->Callbacks().connectionDispatcher().createTimer([this, &timer1, &upstreamChannel, &upstreamReadDisableHandle, write_filter, &timer2, &readEnable] {
        auto ch = WaitForNextUpstreamChannel(default_timeout_);
        ASSERT_OK(ch);
        upstreamChannel.emplace(std::move(ch).value());
        // this message should not be read from the upstream until reads are re-enabled
        upstreamChannel->dispatcher.post([&upstreamChannel] {
          upstreamChannel->channel_callbacks.sendMessageLocal(wire::ChannelDataMsg{
            .data = "asdf"_bytes,
          });
        });

        timer2 = write_filter->Callbacks().connectionDispatcher().createTimer([&timer2, &upstreamReadDisableHandle, &readEnable] {
          readEnable.Call();
          upstreamReadDisableHandle.reset();
          timer2.reset();
        });
        timer2->enableTimer(std::chrono::milliseconds{100});
        timer1.reset();
      });
      timer1->enableTimer(std::chrono::milliseconds{100});
      return absl::OkStatus();
    });
  EXPECT_CALL(readEnable, Call())
    .InSequence(s1, s2);

  // These next two calls can happen in either order
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelDataMsg, _)))
    .InSequence(s1);
  EXPECT_CALL(clientChannelOpened, Call())
    .InSequence(s2);

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)))
    .InSequence(s1, s2);
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)))
    .InSequence(s1, s2);

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
      return absl::OkStatus();
    };
  };
  ASSERT_TRUE(listenForSshConnection(std::move(opts)));

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1)
      .then(driver1_->createTask<Tasks::Call>([&] { clientChannelOpened.Call(); })
              .then(driver1_->createTask<Tasks::WaitForChannelData>("asdf")
                      .then(driver1_->createTask<Tasks::SendChannelCloseAndWait>())))
      .start()));

  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestWriteFilterPauseDuringChannelOpenConfirmationThenInterruptReadFilter) {
  // Test interrupting the read filter while the ChannelOpenConfirmation is queued because the write
  // filter paused the connection before forwarding the message

  // In this scenario, when the read filter is interrupted it will send a ChannelOpenFailure to
  // the downstream and a ChannelClose to the upstream. The upstream will reply with a ChannelClose
  // but it will be read-disabled, so the channel will be closed immediately when upstream reads are
  // re-enabled.

  ReadDisableHandlePtr upstreamReadDisableHandle; // not owned by test thread
  Envoy::Event::TimerPtr timer1;                  // not owned by test thread
  testing::MockFunction<void()> upstreamChannelCloseReceived;
  testing::MockFunction<void()> readEnable;
  TestChannelFilter* readFilter{};
  std::atomic<bool> wasReadEnabled{false};

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)))
    .WillOnce([&readFilter](TestChannelFilter* read_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      readFilter = read_filter;
      return absl::OkStatus();
    });
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([&wasReadEnabled, &upstreamReadDisableHandle, &readFilter, &timer1, &readEnable](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      upstreamReadDisableHandle = write_filter->Callbacks().connectionReadDisable();
      EXPECT_TRUE(readFilter->Callbacks().interruptChannel(absl::InternalError("test error")));

      timer1 = write_filter->Callbacks().connectionDispatcher().createTimer([&wasReadEnabled, &timer1, &upstreamReadDisableHandle, &readEnable] {
        readEnable.Call();
        upstreamReadDisableHandle.reset();
        wasReadEnabled = true;

        timer1.reset();
      });
      timer1->enableTimer(std::chrono::milliseconds{100});
      return absl::OkStatus();
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)));
  EXPECT_CALL(upstreamChannelCloseReceived, Call());

  EXPECT_CALL(readEnable, Call());

  absl::Notification done;
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _))) // will be dropped
    .WillOnce(InvokeWithoutArgs([&] {
      done.Notify();
      return absl::OkStatus();
    }));

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [&upstreamChannelCloseReceived](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [&upstreamChannelCloseReceived](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      upstreamChannelCloseReceived.Call();
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
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

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);

  EXPECT_TRUE(done.WaitForNotificationWithTimeout(default_timeout_))
    << "timed out waiting for ChannelCloseMsg to be forwarded from upstream";
  ASSERT_EQ(true, wasReadEnabled.load());

  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestWriteFilterPauseDuringChannelOpenFailure) {
  // Test pausing the write filter while it is processing a ChannelOpenFailure.

  // In this scenario, pausing the write filter will briefly queue the ChannelOpenFailure message,
  // but because reading a ChannelOpenFailure will destroy the channel, the queue will be flushed
  // right away and the message will be forwarded.

  upstream_accepts_channels_ = false;

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenFailureMsg, _)))
    .WillOnce([](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      auto handle = write_filter->Callbacks().connectionReadDisable();
      write_filter->TakeReadDisableHandle(std::move(handle));
      return absl::OkStatus();
    });

  ASSERT_TRUE(StartListeningForNewSshConnection());

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1, Tasks::ExpectSuccess(false))
      .start()));
  // Both channels should be destroyed at the time the task returns

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);

  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestWriteFilterPauseDuringChannelClose) {
  // Similar to the previous test, but with ChannelCloseMsg.

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)));

  ASSERT_TRUE(StartListeningForNewSshConnection());

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  Tasks::Channel ch;
  EXPECT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1)
      .saveOutput(&ch)
      .start()));

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)))
    .WillOnce([](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      auto handle = write_filter->Callbacks().connectionReadDisable();
      write_filter->TakeReadDisableHandle(std::move(handle));
      return absl::OkStatus();
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)));

  auto task = driver1_->createTask<Tasks::WaitForChannelCloseByPeer>()
                .start(ch);

  upstreamChannel->dispatcher.post([&] {
    upstreamChannel->channel_callbacks.sendMessageLocal(wire::ChannelCloseMsg{});
  });

  ASSERT_TRUE(driver1_->wait(task));
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestDownstreamDisconnectWhileWriteFilterReadDisabled) {
  // Tests the following scenario:
  // 1. The write filter is paused while processing ChannelOpenConfirmation, queueing the message
  // 2. The read filter is interrupted, causing the downstream to be sent a ChannelOpenFailure,
  //    and the upstream to be sent a ChannelClose
  // 4. The upstream receives the ChannelClose and replies with its own ChannelClose, which is
  //    buffered due to being read-disabled
  // 5. The downstream disconnects, tearing down the filter chain and destroying the paused channel
  //    filter
  // 6. When the upstream channel is destroyed, it should free the ReadDisableHandle and flush the
  //    ChannelOpenConfirmation, which should be dropped. The ChannelClose from the upstream will
  //    be left in the read buffer because the codec will be destroyed before the next read event.

  testing::MockFunction<void()> upstreamChannelCloseReceived;
  TestChannelFilter* readFilter{};

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)))
    .WillOnce([&readFilter](TestChannelFilter* read_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      readFilter = read_filter;
      return absl::OkStatus();
    });
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([&readFilter](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      auto readDisableHandle = write_filter->Callbacks().connectionReadDisable();
      write_filter->TakeReadDisableHandle(std::move(readDisableHandle));
      EXPECT_TRUE(readFilter->Callbacks().interruptChannel(absl::InternalError("test error")));
      return absl::OkStatus();
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)));
  EXPECT_CALL(upstreamChannelCloseReceived, Call());

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [&upstreamChannelCloseReceived](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [&upstreamChannelCloseReceived](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      upstreamChannelCloseReceived.Call();
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
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

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);
  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestWriteFilterPauseDuringChannelOpenConfirmationThenInterruptWriteFilter) {
  // Test interrupting the write filter while the ChannelOpenConfirmation is queued because the
  // write filter paused the connection before forwarding the message

  // In this scenario, the upstream channel has received the ChannelOpenConfirmation and its state
  // has transitioned from Pending to Bound, but the downstream channel will remain Pending while
  // the ChannelOpenConfirmation is queued. When the upstream channel is preempted, since it is
  // open from the perspective of the upstream server, a ChannelClose message will be sent locally.
  // The downstream will remain Pending. The upstream server will respond with a ChannelClose
  // message which will be buffered by envoy because the upstream is read-disabled.
  //
  // This case requires special attention, because normally what would happen is the upstream close
  // timer would activate, but the ChannelClose reply can't be received from the upstream, so it
  // would force a timeout unless the channel filter decides to re-enable reads early. If the
  // timeout activates it would trigger a disconnect (since it thinks the server is misbehaving),
  // which may not be intended.
  //
  // The close timer could be paused during this time, but if the channel filter never re-enables
  // reads and the downstream never disconnects, the connection would be held open indefinitely.
  // An upstream disconnect event won't be received while the connection is read-disabled (todo:
  // add a test for this?).
  //
  // Another option would be to force re-enable reads. This would send the ChannelOpenConfirmation
  // to the downstream, followed by anything the upstream channel might have sent before replying
  // to the ChannelClose from the preemption, followed by the ChannelClose. Then the downstream's
  // ChannelClose would be dropped when it attempts to forward it, because the upstream channel
  // would be in the Bereft state after being destroyed.
  //
  // It may not be desirable for the upstream to be sent all the queued messages, but the current
  // system does not have the ability to send a ChannelOpenFailure to the downstream in this state
  // without triggering a disconnect if the queued messages end up being sent later. Both sides of
  // the connection cannot be preempted at the same time, but preemption is the only mechanism by
  // which messages can be dropped. To avoid sending the queued messages, a channel filter can
  // simply preempt the downstream channel instead if they wish. The filter would have had that
  // chance when processing the downstream's ChannelOpen. Also, if e.g. the ChannelOpen contained
  // an exec command, that command would actually have been run on the server no matter what, so it
  // makes sense for that response to be processed as well.

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      auto readDisableHandle = write_filter->Callbacks().connectionReadDisable();
      write_filter->TakeReadDisableHandle(std::move(readDisableHandle));
      EXPECT_TRUE(write_filter->Callbacks().interruptChannel(absl::InternalError("test error")));
      return absl::OkStatus();
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)));

  auto opts = NewDefaultFakeUpstreamHandlerOpts();
  opts.on_channel_open_request = [](wire::ChannelOpenMsg&) -> ChannelMsgHandlerFunc {
    return [](wire::ChannelMessage&& msg, ChannelCallbacks& callbacks) -> absl::Status {
      EXPECT_EQ(wire::SshMessageType::ChannelClose, msg.msg_type());
      callbacks.sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks.channelId(),
      });
      return absl::OkStatus();
    };
  };
  ASSERT_TRUE(listenForSshConnection(std::move(opts)));

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  // If the upstream connection isn't forcibly read-enabled, a DisconnectMsg will be received in
  // 5 seconds after the close timer elapses. The wait() below times out in 10s by default.
  Tasks::Channel ch1;
  ASSERT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1)
      .saveOutput(&ch1)
      .start()));

  // At this point the upstream channel will be closed or in the process of closing. The upstream
  // channel state will at least be preempted-closed, since we would have sent it a ChannelClose
  // internally. The upstream server may or may not disconnect (TODO: check openssh logic) but if
  // it doesn't then the downstream will have time to process the ChannelClose and respond.

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->on_channel_destroyed->WaitForNotificationWithTimeout(default_timeout_);

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _))); // will be dropped
  ASSERT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::WaitForChannelCloseByPeer>()
      .start(ch1)));

  ASSERT_TRUE(driver1_->disconnect());
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestUpstreamResumeReadsOnServerDrain) {
  // Test that on drain/shutdown, upstream connections that were read-disabled due to channel filter
  // request are re-enabled. If they are not, then in some specific cases it can cause the drain to
  // be held up indefinitely until the channel filter resumes reads. Channel filters should not be
  // able to delay shutdown (though their host extensions can).
  //
  // When a server drain happens, it will try to preempt the downstream channel. If the downstream
  // channel is not eligible for preemption, the server will do nothing and wait for the channel to
  // close on its own. If this close sequence is being held up because a ChannelClose cannot be
  // read from the upstream due to it being read-disabled, this will delay the server drain until
  // the upstream reads are re-enabled.
  //
  // One way to get to this state is by reading a ChannelClose message from the downstream while
  // the upstream is read-disabled. In this case there is no channel close timer, and because the
  // downstream channel will be released it will no longer be eligible for preemption. The upstream
  // server will have received the ChannelClose but its reply will be held in the read buffer.

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  TestChannelFilter* writeFilter{};
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([&writeFilter](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      writeFilter = write_filter;
      return absl::OkStatus();
    });

  ASSERT_TRUE(StartListeningForNewSshConnection());

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  Tasks::Channel ch1;
  ASSERT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::OpenSessionChannel>(1)
      .saveOutput(&ch1)
      .start()));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)))
    .WillOnce(InvokeWithoutArgs([this, &writeFilter] {
      auto handle = writeFilter->Callbacks().connectionReadDisable();
      writeFilter->TakeReadDisableHandle(std::move(handle));

      test_server_->server().dispatcher().post([this] {
        test_server_->server().drainManager().startDrainSequence(Network::DrainDirection::All, [] {});
      });
      return absl::OkStatus();
    }));

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)));

  ASSERT_TRUE(driver1_->wait(
    driver1_->createTask<Tasks::SendChannelCloseAndWait>()
      .then(driver1_->createTask<Tasks::WaitForDisconnectWithError>("server shutting down"))
      .start(ch1)));
  driver1_->close();
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadDisableAfterServerDrain) {
  // Test that calling connectionReadDisable() while the server is draining will do nothing

  IN_SEQUENCE;
  EXPECT_CALL(on_channel_filter_factory_created_fn_, Call(0));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Read));
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelOpenMsg, _)));
  EXPECT_CALL(on_channel_filter_created_fn_, Call(_, 0, 0, "driver1", Write));

  absl::Notification channelOpenConfirmationSent;

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelOpenConfirmationMsg, _)))
    .WillOnce([&channelOpenConfirmationSent](TestChannelFilter*, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      channelOpenConfirmationSent.Notify();
      return absl::OkStatus();
    });

  absl::Notification channelData2Sent;

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "1"_bytes))))
    .WillOnce([&channelData2Sent, this](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) mutable {
      auto handle = write_filter->Callbacks().connectionReadDisable();
      write_filter->TakeReadDisableHandle(std::move(handle));

      auto ch = WaitForNextUpstreamChannel(default_timeout_);
      EXPECT_OK(ch);
      if (ch.ok()) {
        ch->dispatcher.post([&channelData2Sent, callbacks = &ch->channel_callbacks] {
          callbacks->sendMessageLocal(wire::ChannelDataMsg{
            .data = "2"_bytes,
          });
          channelData2Sent.Notify();
        });
      }

      return absl::OkStatus();
    });
  ASSERT_TRUE(StartListeningForNewSshConnection());

  driver1_ = makeSshConnectionDriver();
  driver1_->connect();
  ASSERT_TRUE(driver1_->waitForKex());
  ASSERT_TRUE(WaitForDriver1Authenticated());

  auto task = driver1_->createTask<Tasks::OpenSessionChannel>(1)
                .then(driver1_->createTask<Tasks::WaitForChannelData>("1")
                        .then(driver1_->createTask<Tasks::WaitForChannelData>("2")             // should not be blocked
                                .then(driver1_->createTask<Tasks::WaitForChannelCloseByPeer>() // should not be blocked
                                        .then(driver1_->createTask<Tasks::WaitForDisconnectWithError>("server shutting down")))))
                .start();

  {
    Envoy::Event::TestTimeSystem::RealTimeBound bound(absl::ToChronoMilliseconds(default_timeout_));
    while (!channelOpenConfirmationSent.HasBeenNotified() && bound.withinBound() && !HasFailure()) {
      driver1_->connectionDispatcher()->run(Envoy::Event::Dispatcher::RunType::NonBlock);
    }
  }

  auto upstreamChannel = WaitForNextUpstreamChannel(default_timeout_);
  ASSERT_OK(upstreamChannel);
  upstreamChannel->dispatcher.post([callbacks = &upstreamChannel->channel_callbacks] {
    callbacks->sendMessageLocal(wire::ChannelDataMsg{
      .data = "1"_bytes,
    });
  });

  {
    Envoy::Event::TestTimeSystem::RealTimeBound bound(absl::ToChronoMilliseconds(default_timeout_));
    while (!channelData2Sent.HasBeenNotified() && bound.withinBound() && !HasFailure()) {
      driver1_->connectionDispatcher()->run(Envoy::Event::Dispatcher::RunType::NonBlock);
    }
  }
  ASSERT_FALSE(HasFailure());

  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Read, MSG(wire::ChannelCloseMsg, _)))
    .WillOnce([](TestChannelFilter* read_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      auto handle = read_filter->Callbacks().connectionReadDisable();
      // The handle should not be null, but it should be an instance of NoopReadDisableHandle.
      // If it is, then the message should not be queued, and the upstream should receive it.
      EXPECT_NE(nullptr, handle);
      return absl::OkStatus();
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelDataMsg, FIELD_EQ(data, "2"_bytes))))
    .WillOnce([](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      auto handle = write_filter->Callbacks().connectionReadDisable();
      // The handle should not be null, but it should be an instance of NoopReadDisableHandle.
      // If it is, then the driver should receive this message and the other messages that follow.
      EXPECT_NE(nullptr, handle);
      return absl::OkStatus();
    });
  EXPECT_CALL(on_message_forward_fn_, Call(_, 0, 0, "driver1", Write, MSG(wire::ChannelCloseMsg, _)))
    .WillOnce([](TestChannelFilter* write_filter, uint32_t, uint32_t, std::string, Direction, const wire::Message&) {
      auto handle = write_filter->Callbacks().connectionReadDisable();
      EXPECT_NE(nullptr, handle);
      return absl::OkStatus();
    });

  test_server_->server().dispatcher().post([this] {
    test_server_->server().drainManager().startDrainSequence(Network::DrainDirection::All, [] {});
  });

  ASSERT_TRUE(driver1_->wait(task));
}

TEST_F(ChannelFilterInterruptIntegrationTest, TestReadDisableOnPreemptedChannel) {
  // Test that calling connectionReadDisable() on a channel filter for a channel that has been
  // preempted will do nothing
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec