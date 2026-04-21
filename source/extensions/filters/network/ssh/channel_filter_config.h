#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/config/typed_config.h"
#include "envoy/server/factory_context.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/ssh/channel_filter.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ChannelFilterFactory {
public:
  virtual ~ChannelFilterFactory() = default;
  virtual ChannelFilterPtr createReadFilter(ChannelFilterCallbacks& channel_callbacks) PURE;
  virtual ChannelFilterPtr createWriteFilter(ChannelFilterCallbacks& channel_callbacks) PURE;
};
using ChannelFilterFactoryPtr = std::unique_ptr<ChannelFilterFactory>;

class ChannelFilterFactoryConfig : public Config::TypedFactory {
public:
  virtual ChannelFilterFactoryPtr createChannelFilterFactory(Envoy::Server::Configuration::ServerFactoryContext& context) PURE;

  std::string category() const override {
    return "pomerium.ssh.channel_filters";
  }
};

class ChannelFilterManager : NonCopyable {
public:
  ChannelFilterManager(Envoy::Server::Configuration::ServerFactoryContext& context,
                       std::vector<std::string> names);

  bool hasFilters() const;
  std::vector<ChannelFilterPtr> createReadFilters(ChannelFilterCallbacks& channel_callbacks);
  std::vector<ChannelFilterPtr> createWriteFilters(ChannelFilterCallbacks& channel_callbacks);

  struct unused_in_this_test {};
  ChannelFilterManager(unused_in_this_test) {}

private:
  std::vector<ChannelFilterFactoryPtr> factories_;
};

using ChannelFilterManagerSharedPtr = std::shared_ptr<ChannelFilterManager>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec