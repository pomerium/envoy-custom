#include "source/extensions/filters/network/ssh/channel_filter_config.h"
#include <ranges>

#pragma clang unsafe_buffer_usage begin
#include "source/common/config/utility.h"
#pragma clang unsafe_buffer_usage end

template class Envoy::Registry::FactoryRegistry<Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ChannelFilterFactoryConfig>;
template class Envoy::Registry::FactoryRegistryProxyImpl<Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ChannelFilterFactoryConfig>;

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ChannelFilterManager::ChannelFilterManager(const ExtensionConfigList& enabled_channel_filters,
                                           Envoy::Server::Configuration::ServerFactoryContext& context)
    : context_(&context) {
  for (const auto& config : enabled_channel_filters) {
    auto* factory = Envoy::Registry::FactoryRegistry<ChannelFilterFactoryConfig>::getFactory(config.name());
    if (factory == nullptr) {
      throw Envoy::EnvoyException(fmt::format("no registered channel filter factory found for name: {}", config.name()));
    }
    auto factoryConfigMsg = Envoy::Config::Utility::translateAnyToFactoryConfig(
      config.typed_config(), context.messageValidationVisitor(), *factory);
    auto filterFactory = factory->createChannelFilterFactory(*factoryConfigMsg, context);
    ASSERT(filterFactory != nullptr);
    factories_[factory->name()] = std::move(filterFactory);
  }
}

size_t ChannelFilterManager::numConfiguredFilters() const {
  return filter_configs_.size();
}

std::vector<std::string> ChannelFilterManager::allFilterNames() const {
  return std::views::keys(filter_configs_) | std::ranges::to<std::vector>();
}

absl::Status ChannelFilterManager::configureFilters(const ExtensionConfigList& configs) {
  std::vector<std::pair<std::string, ProtobufTypes::MessagePtr>> updatedConfigs;
  for (const auto& config : configs) {
    if (!factories_.contains(config.name())) {
      return absl::NotFoundError(fmt::format(
        "authorization server requested an unknown channel filter: '{}' "
        "(the filter may be provided by an extension which was not loaded or failed to load)",
        config.name()));
    }
    auto& factory = factories_[config.name()];
    auto factoryConfig = factory->createEmptyConfigProto();
    auto stat = Envoy::Config::Utility::translateOpaqueConfig(
      config.typed_config(), context_->messageValidationContext().dynamicValidationVisitor(), *factoryConfig);
    if (!stat.ok()) {
      return absl::InternalError(fmt::format("invalid channel filter config: {}", stat.message()));
    }
    updatedConfigs.emplace_back(config.name(), std::move(factoryConfig));
  }
  filter_configs_.swap(updatedConfigs);
  return absl::OkStatus();
}

std::vector<ChannelFilterPtr> ChannelFilterManager::createReadFilters(ChannelFilterCallbacks& channel_callbacks) {
  std::vector<ChannelFilterPtr> out;
  for (const auto& [name, config] : filter_configs_) {
    ASSERT(factories_.contains(name));
    auto filter = factories_[name]->createReadFilter(*config, channel_callbacks);
    if (filter != nullptr) {
      out.push_back(std::move(filter));
    }
  }
  return out;
}

std::vector<ChannelFilterPtr> ChannelFilterManager::createWriteFilters(ChannelFilterCallbacks& channel_callbacks) {
  std::vector<ChannelFilterPtr> out;
  for (const auto& [name, config] : filter_configs_) {
    ASSERT(factories_.contains(name));
    auto filter = factories_[name]->createWriteFilter(*config, channel_callbacks);
    if (filter != nullptr) {
      out.push_back(std::move(filter));
    }
  }
  return out;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec