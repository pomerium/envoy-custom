#pragma once

#include "google/protobuf/message.h"
#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "test/extensions/filters/network/ssh/ssh_integration_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

enum NumClients : int {};
enum NumChannels : int {};
enum ChannelDataMode {
  DownstreamToUpstreamOnly,
  UpstreamToDownstreamOnly,
  Bidirectional,
};
enum CloseMethod {
  ChannelCloseByDownstream,
  ChannelCloseByUpstream,
  ServerShutdown,
  // InterruptByPriorFilter
};

struct TestParams {
  NumClients num_downstream_clients;
  NumChannels num_channel_open_requests_per_client;
  ChannelDataMode channel_data_mode;
  CloseMethod close_method;
};

enum ChannelFilterType {
  ReadFilter = 0,
  WriteFilter = 1,
};

class TestChannelFilter {
public:
  virtual ~TestChannelFilter() = default;
  virtual ChannelFilterType filterType() PURE;
  virtual std::vector<wire::Message>& transcript() PURE;
};

class ChannelFilterConformanceTestEventCallbacks {
public:
  virtual ~ChannelFilterConformanceTestEventCallbacks() = default;

  virtual testing::AssertionResult onChannelFilterCreated(ChannelFilterCallbacks& filter_callbacks, ChannelFilterType filter_type) PURE;
  virtual testing::AssertionResult onChannelFilterDestroyed(ChannelFilterCallbacks& filter_callbacks, TestChannelFilter& test_filter) PURE;
};

class ChannelFilterConformanceTestConfig : public ChannelFilterConformanceTestEventCallbacks {
public:
  virtual ~ChannelFilterConformanceTestConfig() = default;

  virtual void setTestParams(const TestParams& params) {
    test_params_ = params;
  }
  Envoy::OptRef<const TestParams> testParams() const {
    if (!test_params_.has_value()) {
      return std::nullopt;
    }
    return *test_params_;
  }
  virtual std::string extensionId() const PURE;
  virtual std::string extensionPath() const PURE;
  virtual std::string channelFilterName() const PURE;
  virtual std::string workspaceName() const PURE;

  virtual void addExtraClusters(envoy::config::bootstrap::v3::Bootstrap& bootstrap, ConfigHelperShim& config_helper, const std::string& localhost, uint32_t concurrency) PURE;
  virtual void addExtraUpstreams(AddExtraFakeUpstreamApi& api) PURE;
  virtual testing::AssertionResult initialize(SshIntegrationTestApi& api) PURE; // runs after SshIntegrationTest::initialize()
  virtual void cleanup() PURE;                                                  // runs before SshIntegrationTest::cleanup()

  virtual std::unique_ptr<google::protobuf::Message> newExtensionConfig() PURE;
  virtual std::unique_ptr<google::protobuf::Message> newChannelFilterFactoryConfig() PURE;
  virtual std::unique_ptr<google::protobuf::Message> newChannelFilterConfig() PURE;

  enum TestProperties : uint32_t {
    RequiresTestParams = 1 << 0,
    FilterAllowsMultipleSessions = 1 << 1,
  };

  virtual TestProperties properties() const PURE;

private:
  std::optional<TestParams> test_params_;
};

extern std::unique_ptr<ChannelFilterConformanceTestConfig> newChannelFilterConformanceTestConfig();

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec