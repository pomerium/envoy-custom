#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/config/typed_config.h"
#include "envoy/server/factory_context.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ChannelCallbacks;

class ChannelFilter {
public:
};
using ChannelFilterPtr = std::unique_ptr<ChannelFilter>;

class ChannelFilterFactory {
public:
  virtual ~ChannelFilterFactory() = default;
  virtual ChannelFilterPtr createReadFilter(const ChannelCallbacks& channel_callbacks) PURE;
  virtual ChannelFilterPtr createWriteFilter(const ChannelCallbacks& channel_callbacks) PURE;
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
                       std::vector<std::string> names) {
    for (const auto& name : names) {
      auto* factoryConfig = Envoy::Registry::FactoryRegistry<ChannelFilterFactoryConfig>::getFactory(name);
      if (factoryConfig != nullptr) {
        factories_.push_back(factoryConfig->createChannelFilterFactory(context));
      }
    }
  }

  bool hasFilters() const { return !factories_.empty(); }

  std::vector<ChannelFilterPtr> createReadFilters(const ChannelCallbacks& channel_callbacks) {
    std::vector<ChannelFilterPtr> out;
    for (auto& factory : factories_) {
      out.push_back(factory->createReadFilter(channel_callbacks));
    }
    return out;
  }

  std::vector<ChannelFilterPtr> createWriteFilters(const ChannelCallbacks& channel_callbacks) {
    std::vector<ChannelFilterPtr> out;
    for (auto& factory : factories_) {
      out.push_back(factory->createWriteFilter(channel_callbacks));
    }
    return out;
  }

private:
  std::vector<ChannelFilterFactoryPtr> factories_;
};

using ChannelFilterManagerSharedPtr = std::shared_ptr<ChannelFilterManager>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec