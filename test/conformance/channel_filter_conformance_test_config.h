#pragma once

#include "google/protobuf/message.h"
#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "test/extensions/filters/network/ssh/ssh_integration_common.h"

namespace test {

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::SshIntegrationTestApi;

class ChannelFilterConformanceTestConfig {
public:
  virtual ~ChannelFilterConformanceTestConfig() = default;

  virtual std::string extensionId() const = 0;
  virtual std::string extensionPath() const = 0;
  virtual std::string channelFilterName() const = 0;
  virtual std::string workspaceName() const = 0;

  virtual void addConfigModifier(envoy::config::bootstrap::v3::Bootstrap& bootstrap) = 0;
  virtual void onTestInitialize(SshIntegrationTestApi& api) = 0;
  virtual void onTestCleanup() = 0;

  virtual std::unique_ptr<google::protobuf::Message> newExtensionConfig() = 0;
  virtual std::unique_ptr<google::protobuf::Message> newChannelFilterFactoryConfig() = 0;
  virtual std::unique_ptr<google::protobuf::Message> newChannelFilterConfig() = 0;

  enum FilterProperties : uint32_t {
    FilterAllowsMultipleSessions = 1 << 0,
  };

  virtual FilterProperties filterProperties() const = 0;
};

extern std::unique_ptr<ChannelFilterConformanceTestConfig> newConfig();

} // namespace test