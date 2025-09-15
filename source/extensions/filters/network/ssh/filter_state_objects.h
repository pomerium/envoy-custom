#pragma once

#include <string_view>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

constexpr std::string_view ChannelIDManagerFilterStateKey = "pomerium.extensions.ssh.channel_id_manager";
constexpr std::string_view AuthInfoFilterStateKey = "pomerium.extensions.ssh.auth_info";

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec