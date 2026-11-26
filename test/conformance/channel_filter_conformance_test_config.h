#pragma once

#include "google/protobuf/message.h"
#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "test/extensions/filters/network/ssh/ssh_integration_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class ChannelFilterConformanceTestConfig {
public:
  virtual ~ChannelFilterConformanceTestConfig() = default;

  virtual std::string extensionId() const = 0;
  virtual std::string extensionPath() const = 0;
  virtual std::string channelFilterName() const = 0;
  virtual std::string workspaceName() const = 0;

  virtual void addExtraClusters(envoy::config::bootstrap::v3::Bootstrap& bootstrap, ConfigHelperShim& config_helper, const std::string& localhost) = 0;
  virtual void addExtraUpstreams(AddExtraFakeUpstreamApi& api) = 0;
  virtual testing::AssertionResult initialize(SshIntegrationTestApi& api) = 0; // runs after SshIntegrationTest::initialize()
  virtual void cleanup() = 0;                                                  // runs before SshIntegrationTest::cleanup()

  virtual std::unique_ptr<google::protobuf::Message> newExtensionConfig() = 0;
  virtual std::unique_ptr<google::protobuf::Message> newChannelFilterFactoryConfig() = 0;
  virtual std::unique_ptr<google::protobuf::Message> newChannelFilterConfig() = 0;

  enum FilterProperties : uint32_t {
    FilterAllowsMultipleSessions = 1 << 0,
  };

  virtual FilterProperties filterProperties() const = 0;
};

extern std::unique_ptr<ChannelFilterConformanceTestConfig> newChannelFilterConformanceTestConfig();

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec