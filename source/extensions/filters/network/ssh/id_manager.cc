#include "source/extensions/filters/network/ssh/id_manager.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<uint32_t> ChannelIDManager::allocateNewChannel(Peer owner) {
  auto id = id_alloc_.alloc();
  if (!id.ok()) {
    return id.status();
  }
  ENVOY_LOG(debug, "allocated internal channel ID {} (owner: {})", *id, owner);
  internal_channels_[*id] = InternalChannelInfo{
    .owner = owner,
  };
  return *id;
}

absl::Status ChannelIDManager::trackRelativeID(uint32_t internal_id, RelativeChannelID relative_id) {
  auto it = internal_channels_.find(internal_id);
  if (it == internal_channels_.end()) {
    return absl::InvalidArgumentError(fmt::format("unknown channel {}", internal_id));
  }
  ENVOY_LOG(debug, "{} channel ID {} tracking internal ID {}",
            relative_id.relative_to, relative_id.channel_id, internal_id);
  it->second.peer_ids[relative_id.relative_to] = relative_id.channel_id;
  it->second.peer_states[relative_id.relative_to] = InternalChannelInfo::Tracked;
  return absl::OkStatus();
}

void ChannelIDManager::releaseChannel(uint32_t internal_id, Peer local_peer) {
  ASSERT(internal_channels_.contains(internal_id));
  auto& internalChannel = internal_channels_[internal_id];
  internalChannel.peer_states[local_peer] = InternalChannelInfo::Released;

  if (internalChannel.peer_states[Downstream] != InternalChannelInfo::Tracked &&
      internalChannel.peer_states[Upstream] != InternalChannelInfo::Tracked) {
    ENVOY_LOG(debug, "released internal channel ID [U:{} I:{} D:{}] (owner: {})",
              internalChannel.peer_states[Upstream] == InternalChannelInfo::Released
                ? fmt::to_string(internalChannel.peer_ids[Upstream])
                : "none",
              internal_id,
              internalChannel.peer_states[Downstream] == InternalChannelInfo::Released
                ? fmt::to_string(internalChannel.peer_ids[Downstream])
                : "none",
              internalChannel.owner);
    internal_channels_.erase(internal_id);
    id_alloc_.release(internal_id);
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec