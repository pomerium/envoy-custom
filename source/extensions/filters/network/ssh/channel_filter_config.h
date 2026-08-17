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
  virtual ProtobufTypes::MessagePtr createEmptyConfigProto() PURE;
  virtual absl::StatusOr<ChannelFilterPtr> createReadFilter(const google::protobuf::Message& config, ChannelFilterCallbacks& channel_callbacks) PURE;
  virtual absl::StatusOr<ChannelFilterPtr> createWriteFilter(const google::protobuf::Message& config, ChannelFilterCallbacks& channel_callbacks) PURE;
};
using ChannelFilterFactoryPtr = std::unique_ptr<ChannelFilterFactory>;

class ChannelFilterFactoryConfig : public Config::TypedFactory {
public:
  virtual ChannelFilterFactoryPtr createChannelFilterFactory(const google::protobuf::Message& config,
                                                             Envoy::Server::Configuration::ServerFactoryContext& context) PURE;

  std::string category() const override {
    return "pomerium.ssh.channel_filters";
  }
};

using ExtensionConfigList = google::protobuf::RepeatedPtrField<envoy::config::core::v3::TypedExtensionConfig>;
using ChannelFilterPtrVector = std::vector<ChannelFilterPtr>;

class ChannelFilterManager : NonCopyable,
                             public StreamInfo::FilterState::Object {
public:
  ChannelFilterManager(const ExtensionConfigList& enabled_channel_filters,
                       Envoy::Server::Configuration::ServerFactoryContext& context);

  size_t numConfiguredFilters() const;
  std::vector<std::string> allFilterNames() const;
  absl::Status configureFilters(const ExtensionConfigList& configs);

  absl::StatusOr<ChannelFilterPtrVector> createReadFilters(ChannelFilterCallbacks& channel_callbacks);
  absl::StatusOr<ChannelFilterPtrVector> createWriteFilters(ChannelFilterCallbacks& channel_callbacks);

  struct unused_in_this_test {};
  ChannelFilterManager(unused_in_this_test) {}

private:
  Envoy::Server::Configuration::ServerFactoryContext* context_{};
  std::unordered_map<std::string, ChannelFilterFactoryPtr> factories_;
  std::vector<std::pair<std::string, ProtobufTypes::MessagePtr>> filter_configs_;
};

using ChannelFilterManagerSharedPtr = std::shared_ptr<ChannelFilterManager>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

extern template class Envoy::Registry::FactoryRegistry<Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ChannelFilterFactoryConfig>;
extern template class Envoy::Registry::FactoryRegistryProxyImpl<Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ChannelFilterFactoryConfig>;