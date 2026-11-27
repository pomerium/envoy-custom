#include "api/extensions/bootstrap/dynamic_extension_loader/dynamic_extension_loader.pb.h"
#include "source/extensions/filters/network/ssh/channel_filter.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_task.h"
#include "test/test_common/status_utility.h"
#include "gtest/gtest.h"
#include <barrier>
#include <thread>
#include "test/extensions/filters/network/ssh/ssh_integration_test.h"
#include "test/test_common/registry.h"
#include "envoy/extensions/filters/network/generic_proxy/v3/generic_proxy.pb.h"

#include "test/conformance/channel_filter_conformance_test_config.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

enum SyncPoint {
  CreateEmptyConfigProto,
  CreateReadFilter,
  CreateWriteFilter,

  NumSyncPoints,
};

struct Synchronizer {
  Synchronizer(std::unordered_set<SyncPoint> enabled_sync_points, ptrdiff_t concurrency, bool once)
      : barriers_([&]<size_t... I>(std::index_sequence<I...>) {
          return std::array{std::barrier<std::function<void()>>{
            concurrency, [this, once] { setEnabled(I, !once); }}...};
        }(std::make_index_sequence<NumSyncPoints>())) {
    for (size_t i = 0; i < NumSyncPoints; i++) {
      enabled_[i] = enabled_sync_points.contains(static_cast<SyncPoint>(i));
    }
  }

  template <SyncPoint SP>
  void syncPoint() {
    if (enabled_[SP]) {
      ENVOY_LOG_MISC(info, "thread {} arrived at sync point {}", std::this_thread::get_id(), std::to_underlying(SP));
      barriers_[SP].arrive_and_wait();
      ENVOY_LOG_MISC(info, "thread {} resuming after sync point {}", std::this_thread::get_id(), std::to_underlying(SP));
    }
  }

private:
  void setEnabled(size_t index, bool enabled) {
    enabled_[index] = enabled;
  }
  std::array<bool, NumSyncPoints> enabled_;
  std::array<std::barrier<std::function<void()>>, NumSyncPoints> barriers_;
};

class ShimChannelFilterCallbacks : public ChannelFilterCallbacks {
public:
  ShimChannelFilterCallbacks(ChannelFilterCallbacks& base, ChannelFilterType type)
      : base_(base),
        type_(type) {}

  bool interruptChannel(absl::Status err) override {
    return base_.interruptChannel(std::move(err));
  }

  stream_id_t streamId() const override {
    return base_.streamId();
  }

  const AuthInfo& authInfo() const override {
    return base_.authInfo();
  }

  Envoy::Event::Dispatcher& connectionDispatcher() const override {
    return base_.connectionDispatcher();
  }

  ReadDisableHandlePtr connectionReadDisable() override {
    return base_.connectionReadDisable();
  }

  uint32_t channelId() const override {
    return base_.channelId();
  }

  std::optional<std::string_view> channelType() const override {
    return base_.channelType();
  }

  Stats::Scope& scope() const override {
    return base_.scope();
  }

  ChannelFilterType getFilterType() const { return type_; }

private:
  ChannelFilterCallbacks& base_;
  ChannelFilterType type_;
};

class ShimChannelFilter : private std::unique_ptr<ShimChannelFilterCallbacks>, // destroyed after ChannelFilter
                          public ChannelFilter,
                          public TestChannelFilter {
public:
  ShimChannelFilter(ChannelFilterPtr base, std::unique_ptr<ShimChannelFilterCallbacks> shim_callbacks,
                    ChannelFilterConformanceTestEventCallbacks& event_callbacks)
      : std::unique_ptr<ShimChannelFilterCallbacks>(std::move(shim_callbacks)),
        base_(std::move(base)),
        event_callbacks_(event_callbacks) {
    EXPECT_TRUE(event_callbacks_.onChannelFilterCreated(
      *std::unique_ptr<ShimChannelFilterCallbacks>::get(), filterType()));
  }

  ~ShimChannelFilter() {
    EXPECT_TRUE(event_callbacks_.onChannelFilterDestroyed(
      *std::unique_ptr<ShimChannelFilterCallbacks>::get(), *this));
  }

  absl::Status onMessageForward(const wire::Message& msg) override {
    transcript_.push_back(msg);
    return base_->onMessageForward(msg);
  }

  ChannelFilterType filterType() override {
    return std::unique_ptr<ShimChannelFilterCallbacks>::get()->getFilterType();
  }

  std::vector<wire::Message>& transcript() override {
    return transcript_;
  }

private:
  ChannelFilterPtr base_;
  ChannelFilterConformanceTestEventCallbacks& event_callbacks_;
  std::vector<wire::Message> transcript_;
};

class ShimChannelFilterFactory : public ChannelFilterFactory {
public:
  ShimChannelFilterFactory(std::unique_ptr<ChannelFilterFactory> base, Synchronizer& sync,
                           ChannelFilterConformanceTestEventCallbacks& event_callbacks)
      : base_(std::move(base)),
        event_callbacks_(event_callbacks),
        sync_(sync) {
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    sync_.syncPoint<CreateEmptyConfigProto>();
    return base_->createEmptyConfigProto();
  }

  absl::StatusOr<ChannelFilterPtr> createReadFilter(const google::protobuf::Message& config,
                                                    ChannelFilterCallbacks& channel_callbacks) override {
    sync_.syncPoint<CreateReadFilter>();
    auto shimCallbacks = std::make_unique<ShimChannelFilterCallbacks>(channel_callbacks, ReadFilter);
    auto filter = base_->createReadFilter(config, *shimCallbacks);
    if (!filter.ok()) {
      return filter.status();
    }
    auto shimFilter = std::make_unique<ShimChannelFilter>(std::move(filter).value(), std::move(shimCallbacks), event_callbacks_);
    return shimFilter;
  }

  absl::StatusOr<ChannelFilterPtr> createWriteFilter(const google::protobuf::Message& config,
                                                     ChannelFilterCallbacks& channel_callbacks) override {
    sync_.syncPoint<CreateWriteFilter>();
    auto shimCallbacks = std::make_unique<ShimChannelFilterCallbacks>(channel_callbacks, WriteFilter);
    auto filter = base_->createWriteFilter(config, *shimCallbacks);
    if (!filter.ok()) {
      return filter.status();
    }
    auto shimFilter = std::make_unique<ShimChannelFilter>(std::move(filter).value(), std::move(shimCallbacks), event_callbacks_);
    return shimFilter;
  }

private:
  std::unique_ptr<ChannelFilterFactory> base_;
  ChannelFilterConformanceTestEventCallbacks& event_callbacks_;

  Synchronizer& sync_;
};

class ShimChannelFilterFactoryConfig : public ChannelFilterFactoryConfig {
public:
  ShimChannelFilterFactoryConfig(ChannelFilterFactoryConfig* original, Synchronizer& sync,
                                 ChannelFilterConformanceTestEventCallbacks& event_callbacks)
      : event_callbacks_(event_callbacks),
        sync_(sync),
        original_(original) {
  }

  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return original_->createEmptyConfigProto();
  }

  std::string name() const override {
    return original_->name();
  }

  virtual ChannelFilterFactoryPtr createChannelFilterFactory(const google::protobuf::Message& config,
                                                             Envoy::Server::Configuration::ServerFactoryContext& context) override {
    auto base = original_->createChannelFilterFactory(config, context);
    return std::make_unique<ShimChannelFilterFactory>(std::move(base), sync_, event_callbacks_);
  }

private:
  ChannelFilterConformanceTestEventCallbacks& event_callbacks_;
  Synchronizer& sync_;
  ChannelFilterFactoryConfig* original_;
};

class ChannelFilterConformanceTest : public testing::Test,
                                     public SshIntegrationTest {
public:
  ChannelFilterConformanceTest(std::unordered_set<SyncPoint> enabled_sync_points, size_t concurrency, bool sync_once)
      : SshIntegrationTest({"upstream1"}, Envoy::Network::Address::IpVersion::v4),
        config_(newChannelFilterConformanceTestConfig()),
        thread_synchronizer_(enabled_sync_points, concurrency, sync_once) {
  }

  ChannelFilterConformanceTest()
      : ChannelFilterConformanceTest({}, 0, false) {}

protected:
  void addExtraClusters(envoy::config::bootstrap::v3::Bootstrap& bootstrap) override {
    ConfigHelperShimImpl configHelperShim{config_helper_};
    config_->addExtraClusters(bootstrap, configHelperShim, localhost(), concurrency_);
  }

  void addExtraUpstreams() override {
    config_->addExtraUpstreams(*this);
  }

  void initialize() override {
    if ((config_->properties() & ChannelFilterConformanceTestConfig::RequiresTestParams) != 0) {
      ASSERT_TRUE(config_->testParams().has_value());
    }
    ConfigureExtensionLoader();
    // TODO: this part is copied from filter_manager_test.cc, it should be moved into the base integration test
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      for (auto& listener : *bootstrap.mutable_static_resources()->mutable_listeners()) {
        if (listener.name() != "ssh") {
          continue;
        }
        // make sure connections are each handled by a different worker, if multiple workers are
        // configured
        listener.mutable_connection_balance_config()->mutable_exact_balance();

        auto* filter = listener.mutable_filter_chains(0)->mutable_filters(0);
        ASSERT(filter->name() == "generic_proxy"); // sanity check

        envoy::extensions::filters::network::generic_proxy::v3::GenericProxy genericProxyConfig;
        ASSERT_TRUE(filter->typed_config().UnpackTo(&genericProxyConfig));

        pomerium::extensions::ssh::CodecConfig sshCodecConfig;
        ASSERT_TRUE(genericProxyConfig.codec_config().typed_config().UnpackTo(&sshCodecConfig));

        auto* factoryConfig = sshCodecConfig.add_enabled_channel_filter_factories();
        factoryConfig->set_name(config_->channelFilterName());

        auto factoryConfigMsg = config_->newChannelFilterFactoryConfig();
        ASSERT_TRUE(factoryConfigMsg != nullptr);
        ASSERT_TRUE(factoryConfig->mutable_typed_config()->PackFrom(*factoryConfigMsg));

        ASSERT_TRUE(genericProxyConfig.mutable_codec_config()->mutable_typed_config()->PackFrom(sshCodecConfig));

        ASSERT_TRUE(filter->mutable_typed_config()->PackFrom(genericProxyConfig));
        break;
      }
    });

    SshIntegrationTest::initialize();

    auto status = FetchAdminApiStatus();
    ASSERT_OK(status);
    ASSERT_TRUE(CheckExtensionLoaded(*status, config_->extensionId()));

    auto original = Registry::FactoryRegistry<ChannelFilterFactoryConfig>::getFactory(config_->channelFilterName());
    ASSERT(original != nullptr);
    shim_ = std::make_unique<ShimChannelFilterFactoryConfig>(original, thread_synchronizer_, *config_);
    inject_ = std::make_unique<Registry::InjectFactory<ChannelFilterFactoryConfig>>(*shim_);

    ASSERT_TRUE(config_->initialize(*this));
  }

  void ConfigureExtensionLoader() {
    auto path = Envoy::TestEnvironment::runfilesPath(config_->extensionPath(), config_->workspaceName());
    config_helper_.addConfigModifier([=, this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      if (!bootstrap.bootstrap_extensions().empty()) {
        PANIC("test bug: ConfigureExtensionLoader called twice");
      }
      auto* ext = bootstrap.add_bootstrap_extensions();
      ext->set_name("envoy.bootstrap.dynamic_extension_loader");
      pomerium::extensions::dynamic_extension_loader::Config config;
      config.add_paths(path);
      auto filterExtConfig = config_->newExtensionConfig();
      if (filterExtConfig != nullptr) {
        ASSERT_TRUE((*config.mutable_extension_configs())[config_->extensionId()].PackFrom(*filterExtConfig));
      }
      ASSERT_TRUE(ext->mutable_typed_config()->PackFrom(config));
    });
  }

  absl::StatusOr<Envoy::Json::ObjectSharedPtr> FetchAdminApiStatus() {
    auto response = Envoy::IntegrationUtil::makeSingleRequest(
      lookupPort("admin"), "GET", "/dynamic_extensions/status",
      "", Envoy::Http::CodecType::HTTP1, version_);

    if (!response->complete()) {
      return absl::InternalError("admin api request failed");
    }
    return Envoy::Json::Factory::loadFromString(response->body());
  }

  AssertionResult CheckExtensionLoaded(Envoy::Json::ObjectSharedPtr status, std::string id) {
    auto obj = status->getObjectArray("loaded");
    if (!obj.ok()) {
      return AssertionFailure() << obj.status();
    }
    for (const auto& entry : *obj) {
      if (*entry->getString("id") == id) {
        return AssertionSuccess();
      }
    }
    return AssertionFailure() << "extension was not reported as loaded by the admin api";
  }

  AssertionResult WaitForUserAuthWithFilter(std::shared_ptr<SshConnectionDriver> driver) {
    return driver->waitForUserAuth("user", "upstream1", [this](pomerium::extensions::ssh::AllowResponse& allow) {
      ASSERT_TRUE(allow.has_upstream()); // sanity check
      auto* filterConfig = allow.mutable_upstream()->add_channel_filters();
      filterConfig->set_name(config_->channelFilterName());
      auto channelFilterConfig = config_->newChannelFilterConfig();
      ASSERT_TRUE(filterConfig->mutable_typed_config()->PackFrom(*channelFilterConfig));
    });
  }
  absl::StatusOr<std::shared_ptr<SshConnectionDriver>> StartDownstream() {
    auto driver = makeSshConnectionDriver();
    driver->connect();
    if (auto r = driver->waitForKex(); !r) {
      return absl::InternalError(r.message());
    }
    return driver;
  }

  virtual SshFakeUpstreamHandlerOpts NewFakeUpstreamHandlerOpts() {
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

    return SshFakeUpstreamHandlerOpts{
      .on_channel_open_request = onChannelOpenRequest,
    };
  }

  std::unique_ptr<ChannelFilterConformanceTestConfig> config_;
  Synchronizer thread_synchronizer_;
  std::unique_ptr<ShimChannelFilterFactoryConfig> shim_;
  std::unique_ptr<Registry::InjectFactory<ChannelFilterFactoryConfig>> inject_;
};

TEST_F(ChannelFilterConformanceTest, BasicStartup) {
  initialize();
}

// Things to test
// - create <1-4> clients with <1-4> shell channel(s) each, send channel data <c->s|c<-s|c<->s>, close <from client side|from server side|by shutdown>
// - client attempts <1-4> times to create a session channel but server rejects the channel open
// - client attempts <1-4> times to create a <shell|exec|subsystem> channel but server rejects the channel open
// - client attempts to send a second <shell|exec|subsystem> channel request after the first is accepted, which should be rejected by the upstream
// - client sends several channel requests in sequence before the server responds (this should check that the filter is tracking which request each reply corresponds to)

// Filter test options:
// - whether or not the filter allows multiple sessions

class ChannelFilterConformanceTestNormalSession : public testing::WithParamInterface<std::tuple<NumClients, NumChannels, ChannelDataMode, CloseMethod>>,
                                                  public ChannelFilterConformanceTest {
public:
  ChannelFilterConformanceTestNormalSession()
      : ChannelFilterConformanceTest({},
                                     std::get<NumClients>(GetParam()), true) {
    concurrency_ = params_.num_downstream_clients;
    config_->setTestParams(params_);
  }

  void TearDown() override {
    config_->cleanup();
    cleanup();
  }

  TestParams params_{
    .num_downstream_clients = std::get<NumClients>(GetParam()),
    .num_channel_open_requests_per_client = std::get<NumChannels>(GetParam()),
    .channel_data_mode = std::get<ChannelDataMode>(GetParam()),
    .close_method = std::get<CloseMethod>(GetParam()),
  };
};

class SendAndReceiveChannelData : public Task<SendAndReceiveChannelData, Tasks::Channel, Tasks::Channel> {
public:
  explicit SendAndReceiveChannelData(const bytes& expected, size_t num_chunks)
      : expected_data_(to_string(expected)) {
    chunks_ = randomChunks(expected, num_chunks);
  }
  void start(Tasks::Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_);

    if (!chunks_.empty()) {
      callbacks_->loopWhile(std::chrono::milliseconds{0}, [this] -> bool {
        callbacks_->sendMessage(wire::ChannelDataMsg{
          .recipient_channel = channel_.remote_id,
          .data = chunks_[chunks_index_++],
        });
        return chunks_index_ < chunks_.size();
      });
    }
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelDataMsg& data) {
        recv_buffer_.add(data.data->data(), data.data->size());
        if (recv_buffer_.length() >= expected_data_.length()) {
          checkBuffers();
        }
        return Break;
      },
      [&](const wire::ChannelCloseMsg&) {
        taskFailure(absl::InternalError("channel closed before all data was received"));
        return Break;
      },
      [&](const wire::ChannelEOFMsg&) {
        taskFailure(absl::InternalError("got channel EOF before all data was received"));
        return Break;
      },
      [&](const auto&) {
        return Continue;
      });
  }

  void checkBuffers() {
    auto actual = recv_buffer_.toString();
    for (size_t i = 0; i < actual.size(); i++) {
      if (expected_data_[i] != actual[i]) {
        taskFailure(absl::InvalidArgumentError(fmt::format(
          "actual data does not match expected data. mismatch occurred at index {} (expected={}, actual={})", i, expected_data_[i], actual[i])));
        return;
      }
    }
    taskSuccess(channel_);
  }
  const std::string expected_data_;
  std::vector<bytes> chunks_;
  size_t chunks_index_{0};
  Tasks::Channel channel_;
  Envoy::Buffer::OwnedImpl recv_buffer_;
};

TEST_P(ChannelFilterConformanceTestNormalSession, Test) {
  initialize();

  std::vector<std::shared_ptr<SshConnectionDriver>> drivers;
  for (int i = 0; i < params_.num_downstream_clients; i++) {
    ENVOY_LOG_MISC(info, "starting downstream client {}", i + 1);
    auto d = StartDownstream();
    EXPECT_OK(d);
    drivers.push_back(*d);
  }

  for (auto& driver : drivers) {
    EXPECT_TRUE(listenForSshConnection(NewFakeUpstreamHandlerOpts(), 0));
    EXPECT_TRUE(WaitForUserAuthWithFilter(driver));
  }

  ASSERT_FALSE(HasFailure());

  std::vector<std::pair<SshConnectionDriver&, UntypedTaskCallbacksHandle&>> handles;
  for (auto& driver : drivers) {
    for (int i = 0; i < params_.num_channel_open_requests_per_client; i++)
      handles.push_back({*driver, driver->createTask<Tasks::OpenSessionChannel>(i++)
                                    .then(driver->createTask<SendAndReceiveChannelData>(randomBytes(randomInt<size_t>(4096, 16384), 'A', 'z'),
                                                                                        randomInt<size_t>(100, 200))
                                            .then(driver->createTask<Tasks::SendChannelCloseAndWait>()))
                                    .start()});
  }
  ASSERT_TRUE(SshConnectionDriver::waitAll(std::move(handles)));
  for (auto& driver : drivers) {
    EXPECT_TRUE(driver->disconnect());
  }
}

INSTANTIATE_TEST_SUITE_P(ChannelFilterConformanceTestNormalSessionTest, ChannelFilterConformanceTestNormalSession,
                         testing::Values(std::tuple{NumClients(4), NumChannels(1), DownstreamToUpstreamOnly, ChannelCloseByDownstream}));
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec