#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace {
inline bool releaseEligible(ChannelIDState state) {
  return state == ChannelIDState::Unbound ||
         state == ChannelIDState::Released ||
         state == ChannelIDState::Bereft;
}
inline bool preemptEligible(ChannelIDState remote_state) {
  return remote_state == ChannelIDState::Unbound ||
         remote_state == ChannelIDState::Pending ||
         remote_state == ChannelIDState::Bound;
}

} // namespace

absl::StatusOr<uint32_t> ChannelIDManager::allocateNewChannel(Peer owner) {
  if (draining_) {
    return absl::UnavailableError("server is shutting down");
  }
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
absl::Status ChannelIDManager::bindChannelID(uint32_t internal_id, PeerLocalID peer_local_id, bool expect_remote) {
  auto it = internal_channels_.find(internal_id);
  if (it == internal_channels_.end()) {
    return absl::InvalidArgumentError(fmt::format("unknown channel {}", internal_id));
  }
  if (auto localState = it->second.peer_states[peer_local_id.local_peer];
      localState != ChannelIDState::Unbound && localState != ChannelIDState::Pending) {
    return absl::InvalidArgumentError(fmt::format("channel {} is already known to {}",
                                                  internal_id, peer_local_id.local_peer));
  }
  it->second.peer_ids[peer_local_id.local_peer] = peer_local_id.channel_id;
  it->second.peer_states[peer_local_id.local_peer] = ChannelIDState::Bound;
  if (expect_remote) {
    auto remotePeer = peer_local_id.local_peer == Downstream ? Upstream : Downstream;
    if (it->second.peer_states[remotePeer] == ChannelIDState::Unbound) {
      it->second.peer_states[remotePeer] = ChannelIDState::Pending;
    }
  }
  ENVOY_LOG(debug, "channel {}: {} ID bound [{}]", internal_id, peer_local_id.local_peer, it->second);
  return absl::OkStatus();
}

// Note: this should only be called by ChannelCallbacksImpl::cleanup().
void ChannelIDManager::releaseChannelID(uint32_t internal_id, Peer local_peer) {
  ASSERT(internal_channels_.contains(internal_id));
  auto& internalChannel = internal_channels_[internal_id];

  auto currentState = internalChannel.peer_states[local_peer];
  if (currentState == ChannelIDState::Bound || currentState == ChannelIDState::Pending) {
    internalChannel.peer_states[local_peer] = ChannelIDState::Released;
  } else if (currentState == ChannelIDState::Preempted) {
    internalChannel.peer_states[local_peer] = ChannelIDState::Bereft;
  }

  ENVOY_LOG(debug, "channel {}: {} ID released [{}]", internal_id, local_peer, internalChannel);
  if (releaseEligible(internalChannel.peer_states[Peer::Downstream]) &&
      releaseEligible(internalChannel.peer_states[Peer::Upstream])) {
    internal_channels_.erase(internal_id);
    id_alloc_.release(internal_id);
    ENVOY_LOG(debug, "freed internal channel ID {}", internal_id);
    if (draining_ && internal_channels_.empty()) {
      ENVOY_LOG(debug, "channel id manager: drain complete");
      drain_cb_->runCallbacks();
    }
  }
}

std::optional<Peer> ChannelIDManager::owner(uint32_t internal_id) {
  if (!internal_channels_.contains(internal_id)) {
    return std::nullopt;
  }
  return internal_channels_[internal_id].owner;
}

bool ChannelIDManager::isPreemptable(uint32_t internal_id, Peer local_peer) {
  if (!internal_channels_.contains(internal_id)) {
    // this should ideally return nullopt like owner(), but optional<bool> is error-prone
    return false;
  }
  auto localState = internal_channels_[internal_id].peer_states[local_peer];
  auto remoteState = internal_channels_[internal_id].peer_states[local_peer == Downstream
                                                                   ? Upstream
                                                                   : Downstream];

  return (localState == ChannelIDState::Bound && preemptEligible(remoteState));
}

void ChannelIDManager::preempt(uint32_t internal_id, Peer local_peer) {
  ASSERT(isPreemptable(internal_id, local_peer));
  auto& internalChannel = internal_channels_[internal_id];
  internalChannel.peer_states[local_peer] = ChannelIDState::Preempted;
}

std::optional<ChannelIDState> ChannelIDManager::peerState(uint32_t internal_id, Peer peer) {
  if (!internal_channels_.contains(internal_id)) {
    return std::nullopt;
  }
  return internal_channels_[internal_id].peer_states[peer];
}

absl::StatusOr<bool> ChannelIDManager::processOutgoingChannelMsgImpl(wire::field<uint32_t>& recipient_channel,
                                                                     wire::SshMessageType msg_type,
                                                                     Peer dest) {
  uint32_t internalId = *recipient_channel;
  auto it = internal_channels_.find(internalId);
  if (it == internal_channels_.end()) {
    return absl::InvalidArgumentError(fmt::format(
      "error processing outgoing message of type {}: no such channel: {}", msg_type, internalId));
  }

  auto& info = it->second;
  switch (info.peer_states[dest]) {
  [[likely]] default:
    recipient_channel = info.peer_ids[dest];
    return true;
  case ChannelIDState::Unbound:
    [[fallthrough]];
  case ChannelIDState::Pending:
    // There is one scenario where we need to drop messages to a Pending dest peer. If the source
    // peer is in the Preempted state and attempts to forward a ChannelClose message, it is
    // processing the response to a ChannelClose sent via preempt, and immediately after sending
    // this ChannelClose, it will transition to the Bereft state. Then, if the dest peer sends
    // a ChannelOpenConfirmation later, this will trigger it to create a new ForceCloseChannel.
    if (msg_type == wire::SshMessageType::ChannelClose &&
        info.peer_states[dest == Downstream ? Upstream : Downstream] == ChannelIDState::Preempted) {
      return false;
    }
    return absl::InvalidArgumentError(
      fmt::format("error processing outgoing message of type {}: internal channel {} is not known to {} (state: {})",
                  msg_type, internalId, dest, info.peer_states[dest]));
  case ChannelIDState::Preempted:
    if (!info.preempted_closed) {
      // While the channel is in the Preempted state, messages can be sent only until the next
      // ChannelClose, which will set preemptable=false.
      recipient_channel = info.peer_ids[dest];

      if (msg_type == wire::SshMessageType::ChannelClose) {
        info.preempted_closed = true;
      }
      return true;
    }
    // Once the channel has been preempted and closed, further messages are blocked.
    return false;
  case ChannelIDState::Bereft:
    return false;
  }
}

[[nodiscard]]
Envoy::Common::CallbackHandlePtr ChannelIDManager::startDrain(Envoy::Event::Dispatcher& dispatcher, std::function<void()> complete_cb) {
  if (draining_) {
    if (internal_channels_.empty()) {
      dispatcher.post(complete_cb);
      return nullptr;
    }
    return drain_cb_->add(dispatcher, std::move(complete_cb));
  }
  draining_ = true;
  auto handle = drain_cb_->add(dispatcher, std::move(complete_cb));
  if (internal_channels_.empty()) {
    // already drained
    drain_cb_->runCallbacks();
  }
  return handle;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec