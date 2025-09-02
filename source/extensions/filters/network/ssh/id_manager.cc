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

// Note: this should only be called by ConnectionService::handleMessage().
absl::Status ChannelIDManager::bindChannelID(uint32_t internal_id, PeerLocalID peer_local_id) {
  auto it = internal_channels_.find(internal_id);
  if (it == internal_channels_.end()) {
    return absl::InvalidArgumentError(fmt::format("unknown channel {}", internal_id));
  }
  ENVOY_LOG(debug, "{} channel ID {} tracking internal ID {}",
            peer_local_id.local_peer, peer_local_id.channel_id, internal_id);
  it->second.peer_ids[peer_local_id.local_peer] = peer_local_id.channel_id;
  it->second.peer_states[peer_local_id.local_peer] = InternalChannelInfo::Bound;
  return absl::OkStatus();
}

// Note: this should only be called by ChannelCallbacksImpl::cleanup().
void ChannelIDManager::releaseChannelID(uint32_t internal_id, Peer local_peer) {
  ASSERT(internal_channels_.contains(internal_id));
  auto& internalChannel = internal_channels_[internal_id];
  internalChannel.peer_states[local_peer] = InternalChannelInfo::Released;

  if (internalChannel.peer_states[Downstream] != InternalChannelInfo::Bound &&
      internalChannel.peer_states[Upstream] != InternalChannelInfo::Bound) {
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

absl::Status ChannelIDManager::processOutgoingChannelMsgImpl(wire::field<uint32_t>& recipient_channel,
                                                             wire::SshMessageType msg_type,
                                                             Peer dest) {
  uint32_t internalId = *recipient_channel;
  auto it = internal_channels_.find(internalId);
  if (it == internal_channels_.end()) {
    return absl::InvalidArgumentError(fmt::format("unknown channel {} in {}", internalId, msg_type));
  }

  auto& info = it->second;
  if (info.peer_states[dest] == InternalChannelInfo::Unbound) {
    return absl::InvalidArgumentError(
      fmt::format("error processing outgoing {} message: internal channel {} is not known to {} (state: {})",
                  msg_type, internalId, dest, info.peer_states[dest]));
  }
  recipient_channel = info.peer_ids[dest];
  return absl::OkStatus();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec