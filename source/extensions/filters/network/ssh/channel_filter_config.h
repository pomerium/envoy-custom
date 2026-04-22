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
  virtual ChannelFilterPtr createReadFilter(const google::protobuf::Message& config, ChannelFilterCallbacks& channel_callbacks) PURE;
  virtual ChannelFilterPtr createWriteFilter(const google::protobuf::Message& config, ChannelFilterCallbacks& channel_callbacks) PURE;
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

class ChannelFilterManager : NonCopyable {
public:
  ChannelFilterManager(const ExtensionConfigList& enabled_channel_filters,
                       Envoy::Server::Configuration::ServerFactoryContext& context);

  size_t numConfiguredFilters() const;
  absl::Status configureFilters(const ExtensionConfigList& configs);

  std::vector<ChannelFilterPtr> createReadFilters(ChannelFilterCallbacks& channel_callbacks);
  std::vector<ChannelFilterPtr> createWriteFilters(ChannelFilterCallbacks& channel_callbacks);

  struct unused_in_this_test {};
  ChannelFilterManager(unused_in_this_test) {}

private:
  Envoy::Server::Configuration::ServerFactoryContext* context_{};
  std::unordered_map<std::string, ChannelFilterFactoryPtr> factories_;
  std::unordered_map<std::string, ProtobufTypes::MessagePtr> filter_configs_;
};

using ChannelFilterManagerSharedPtr = std::shared_ptr<ChannelFilterManager>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec