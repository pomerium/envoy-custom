#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "fmt/args.h"
#include <utility>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace {
inline bool releaseEligible(ChannelIDState state) {
  return state == ChannelIDState::Unbound ||
         state == ChannelIDState::Released ||
         state == ChannelIDState::Bereft;
}
inline Peer oppositePeer(Peer peer) {
  return peer == Downstream ? Upstream : Downstream;
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
absl::Status ChannelIDManager::bindChannelID(uint32_t internal_id, PeerLocalID peer_local_id, BindMode bind_mode) {
  auto it = internal_channels_.find(internal_id);
  if (it == internal_channels_.end()) {
    return absl::InvalidArgumentError(fmt::format("unknown channel {}", internal_id));
  }
  auto& info = it->second;
  const auto localPeer = peer_local_id.local_peer;
  const auto localState = info.peer_states[localPeer];
  const auto remotePeer = oppositePeer(localPeer);
  const auto remoteState = info.peer_states[remotePeer];
  if ((localState != ChannelIDState::Unbound && localState != ChannelIDState::Pending) ||
      info.peer_ids[localPeer].has_value()) {
    return absl::InvalidArgumentError(fmt::format("channel {} is already known to {}",
                                                  internal_id, localPeer));
  }

  info.peer_ids[localPeer] = peer_local_id.channel_id;

  switch (bind_mode) {
  case BindMode::PendingRemoteConfirmation:
    info.peer_states[localPeer] = ChannelIDState::Pending;
    ENVOY_LOG(debug, "channel {}: {} ID pending [{}]", internal_id, localPeer, info);
    if (remoteState == ChannelIDState::Unbound) {
      info.peer_states[remotePeer] = ChannelIDState::Pending;
      ENVOY_LOG(debug, "channel {}: {} ID pending [{}]", internal_id, remotePeer, info);
    }
    break;
  case BindMode::PendingInternalConfirmation:
    info.peer_states[localPeer] = ChannelIDState::Pending;
    ENVOY_LOG(debug, "channel {}: {} ID pending [{}]", internal_id, localPeer, info);
    break;
  case BindMode::Confirmed:
    // Note: the remote peer does not transition from Pending to Bound until it is forwarded the
    // ChannelOpenConfirmation/Failure via processOutgoingChannelMsg
    info.peer_states[localPeer] = ChannelIDState::Bound;
    ENVOY_LOG(debug, "channel {}: {} ID bound [{}]", internal_id, localPeer, info);
    break;
  }
  return absl::OkStatus();
}

// Note: this should only be called by ChannelCallbacksImpl::cleanup().
void ChannelIDManager::releaseChannelID(uint32_t internal_id, Peer local_peer) {
  ASSERT(internal_channels_.contains(internal_id));
  auto& info = internal_channels_[internal_id];

  const auto localState = info.peer_states[local_peer];
  if (localState == ChannelIDState::Bound || localState == ChannelIDState::Pending) {
    info.peer_states[local_peer] = ChannelIDState::Released;
  } else if (localState == ChannelIDState::Preempted) {
    info.peer_states[local_peer] = ChannelIDState::Bereft;
  }

  ENVOY_LOG(debug, "channel {}: {} ID released [{}]", internal_id, local_peer, info);
  if (releaseEligible(info.peer_states[Peer::Downstream]) &&
      releaseEligible(info.peer_states[Peer::Upstream])) {
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
  using enum ChannelIDState;
  if (!internal_channels_.contains(internal_id)) {
    // this should ideally return nullopt like owner(), but optional<bool> is error-prone
    return false;
  }
  auto& info = internal_channels_[internal_id];
  const auto localState = info.peer_states[local_peer];
  const auto remotePeer = oppositePeer(local_peer);
  const auto remoteState = info.peer_states[remotePeer];

  // The local state must be either Bound or Pending, and if Pending it must have an ID (otherwise
  // there is no action that could be taken). The remote state can't already be preempted or in the
  // process of being closed.
  if (localState != Bound && localState != Pending) {
    return false;
  }
  if (info.peer_ids[local_peer].value_or(channel_id_error) == channel_id_error) {
    return false;
  }
  if (remoteState != Unbound && remoteState != Pending && remoteState != Bound) {
    return false;
  }
  return true;
}

ChannelIDState ChannelIDManager::preempt(uint32_t internal_id, Peer local_peer) {
  ASSERT(isPreemptable(internal_id, local_peer));
  auto& internalChannel = internal_channels_[internal_id];
  return std::exchange(internalChannel.peer_states[local_peer], ChannelIDState::Preempted);
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
  [[likely]] case ChannelIDState::Bound:
    recipient_channel = *info.peer_ids[dest];
    return true;
  case ChannelIDState::Unbound:
    // Even if the peer wasn't previously marked pending, receiving a ChannelOpenConfirmation or
    // ChannelOpenFailure implies that a ChannelOpen was previously sent, so the channel should
    // become Bound.
    [[fallthrough]];
  case ChannelIDState::Pending:
    // Pending channels can only receive ChannelOpenConfirmation or ChannelOpenFailure messages.
    if (info.peer_ids[dest].value_or(channel_id_error) != channel_id_error) {
      switch (msg_type) {
      case wire::SshMessageType::ChannelOpenConfirmation:
        recipient_channel = *info.peer_ids[dest];
        // Transition the dest channel from Pending to Bound
        info.peer_states[dest] = ChannelIDState::Bound;
        ENVOY_LOG(debug, "channel {}: {} ID bound [{}]", internalId, dest, info);
        return true;
      case wire::SshMessageType::ChannelOpenFailure:
        recipient_channel = *info.peer_ids[dest];
        // Keep the dest channel Pending, but clear its local ID. No further messages can be sent
        // after ChannelOpenFailure, and clearing the ID will make it ineligible for subsequent
        // preemption.
        info.peer_ids[dest] = channel_id_error;
        ENVOY_LOG(debug, "channel {}: {} ID cleared [{}]", internalId, Upstream, info);
        return true;
      default:
        break;
      }
    }
    return absl::InvalidArgumentError(
      fmt::format("error processing outgoing message of type {}: internal channel {} is not known to {} (state: {})",
                  msg_type, internalId, dest, info.peer_states[dest]));
  case ChannelIDState::Released:
    if (info.peer_ids[dest].value_or(channel_id_error) == channel_id_error) {
      return absl::InvalidArgumentError(
        fmt::format("error processing outgoing message of type {}: internal channel {} is not known to {} (state: {})",
                    msg_type, internalId, dest, info.peer_states[dest]));
    }
    recipient_channel = info.peer_ids[dest].value();
    return true;
  case ChannelIDState::Preempted:
    if (info.peer_ids[dest].value_or(channel_id_error) != channel_id_error) {
      // While the channel is in the Preempted state, messages can be sent only until the next
      // ChannelClose (or ChannelOpenFailure if never opened), which will clear the id.
      recipient_channel = *info.peer_ids[dest];

      if (msg_type == wire::SshMessageType::ChannelClose ||
          msg_type == wire::SshMessageType::ChannelOpenFailure) {
        info.peer_ids[dest] = channel_id_error;
        ENVOY_LOG(debug, "channel {}: preempted {} ID is closed [{}]", internalId, dest, info);
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

std::string format_as(const InternalChannelInfo& info) {
  fmt::dynamic_format_arg_store<fmt::format_context> args;
  for (auto peer : {Peer::Upstream, Peer::Downstream}) {
    args.push_back(info.owner == peer ? "*" : "");
    args.push_back(info.peer_states[peer]);
    if (info.peer_ids[peer].has_value()) {
      const auto id = info.peer_ids[peer].value();
      args.push_back(":");
      if (id == channel_id_error) {
        if (auto state = info.peer_states[peer];
            state == ChannelIDState::Preempted || state == ChannelIDState::Bereft) {
          args.push_back("<closed>");
        } else {
          args.push_back("<err>");
        }
      } else {
        args.push_back(id);
      }
    } else {
      args.push_back("");
      args.push_back("");
    }
  }
  return fmt::vformat("U{}:{}{}{}|D{}:{}{}{}", args);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec