#include "source/extensions/filters/network/ssh/channel_filter_config.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ChannelFilterManager::ChannelFilterManager(Envoy::Server::Configuration::ServerFactoryContext& context,
                                           std::vector<std::string> names) {
  for (const auto& name : names) {
    auto* factoryConfig = Envoy::Registry::FactoryRegistry<ChannelFilterFactoryConfig>::getFactory(name);
    if (factoryConfig != nullptr) {
      factories_.push_back(factoryConfig->createChannelFilterFactory(context));
    }
  }
}

bool ChannelFilterManager::hasFilters() const {
  return !factories_.empty();
}

std::vector<ChannelFilterPtr> ChannelFilterManager::createReadFilters(ChannelFilterCallbacks& channel_callbacks) {
  std::vector<ChannelFilterPtr> out;
  for (auto& factory : factories_) {
    auto filter = factory->createReadFilter(channel_callbacks);
    if (filter != nullptr) {
      out.push_back(std::move(filter));
    }
  }
  return out;
}

std::vector<ChannelFilterPtr> ChannelFilterManager::createWriteFilters(ChannelFilterCallbacks& channel_callbacks) {
  std::vector<ChannelFilterPtr> out;
  for (auto& factory : factories_) {
    auto filter = factory->createWriteFilter(channel_callbacks);
    if (filter != nullptr) {
      out.push_back(std::move(filter));
    }
  }
  return out;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec