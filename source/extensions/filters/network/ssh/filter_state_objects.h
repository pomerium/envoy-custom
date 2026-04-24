#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/common/network/filter_state_dst_address.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/transport_common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

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

class RequestedPath : public StreamInfo::FilterState::Object {
public:
  RequestedPath(absl::string_view server_name) : server_name_(server_name) {}
  const std::string& value() const { return server_name_; }
  absl::optional<std::string> serializeAsString() const override { return server_name_; }
  static const std::string& key();

private:
  const std::string server_name_;
};

class RequestedPathFilterStateFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override;
  static const std::string& key();
  std::unique_ptr<StreamInfo::FilterState::Object> createFromBytes(absl::string_view data) const override {
    return std::make_unique<RequestedPath>(data);
  }
};

struct AuthInfo : public StreamInfo::FilterState::Object {
  std::string server_version;
  stream_id_t stream_id{}; // unique stream id for both connections
  ChannelMode channel_mode{};
  HandoffInfo handoff_info;
  std::optional<wire::ExtInfoMsg> downstream_ext_info;
  std::optional<wire::ExtInfoMsg> upstream_ext_info;
  std::unique_ptr<pomerium::extensions::ssh::AllowResponse> allow_response;
};

using AuthInfoSharedPtr = std::shared_ptr<AuthInfo>;

constexpr std::string_view ChannelIDManagerFilterStateKey = "pomerium.extensions.ssh.channel_id_manager";
constexpr std::string_view AuthInfoFilterStateKey = "pomerium.extensions.ssh.auth_info";

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec