#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/common/network/filter_state_dst_address.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamSourceAddressFilterStateFactory : public Network::BaseAddressObjectFactory {
public:
  std::string name() const override;
  static const std::string& key();
};

class RequestedServerName : public StreamInfo::FilterState::Object {
public:
  RequestedServerName(absl::string_view server_name) : server_name_(server_name) {}
  const std::string& value() const { return server_name_; }
  absl::optional<std::string> serializeAsString() const override { return server_name_; }
  static const std::string& key();

private:
  const std::string server_name_;
};

class RequestedServerNameFilterStateFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override;
  static const std::string& key();
  std::unique_ptr<StreamInfo::FilterState::Object> createFromBytes(absl::string_view data) const override {
    return std::make_unique<RequestedServerName>(data);
  }
};

constexpr std::string_view ChannelIDManagerFilterStateKey = "pomerium.extensions.ssh.channel_id_manager";

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec