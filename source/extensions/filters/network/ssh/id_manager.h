#pragma once

#include "fmt/args.h"
#include "source/common/id_alloc.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/event/dispatcher.h"
#include "source/common/common/callback_impl.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

constexpr uint32_t DefaultMaxConcurrentChannels = 32768;

enum Peer : uint8_t {
  Downstream = 0,
  Upstream = 1,
};

enum class BindMode {
  // The local ID is for a pending channel that is awaiting confirmation from the remote peer.
  // In this mode, both peers will be set to Pending.
  PendingRemoteConfirmation = 0,
  // The local ID is for a pending channel that is awaiting internal confirmation, and does not yet
  // involve the real remote peer.
  // In this mode, the local peer will be set to Pending, and the remote peer will not be updated.
  PendingInternalConfirmation = 1,
  // The local ID was obtained by receiving a ChannelOpenConfirmation message.
  // In this mode, the local peer will be set to Bound, and the remote peer will not be updated.
  Confirmed = 2,
};

enum class ChannelIDState {
  // Default state. A channel is Unbound until a ChannelOpen request is received from the peer.
  Unbound = 0,
  // A channel is marked Pending when it is awaiting a ChannelOpenConfirmation or ChannelOpenFailure
  // message in reply to a ChannelOpen message. Pending is equivalent to Unbound except that it will
  // prevent the channel from being freed. If a peer is awaiting its opposite peer to bind the same
  // internal channel, the opposite peer is also moved to the Pending state.
  // Pending channels may or may not have an associated peer-local ID. If a Pending channel does
  // have one, it may be
  Pending = 1,
  // A channel is Bound when the peer knows about this channel ID and it has received a
  // ChannelOpenConfirmation message for the channel.
  Bound = 2,
  // A channel is Released when awaiting a close handshake between peers, or awaiting destruction
  // after opening the channel failed. A channel in this state is still active until released by
  // all bound peers. If a released channel was previously bound with a local ID, it can still be
  // sent messages, but messages will not be sent by it.
  Released = 3,
  // A channel becomes Preempted when a ChannelClose is sent from one side of the transport to
  // its local peer. It exists in this state until a corresponding ChannelClose is received,
  // at which point it transitions to Bereft.
  // Transitioning from Bound to Preempted does not release the channel. A preempted channel must
  // still be released later for the ID to become freed.
  // Messages may only be sent to the peer for channels in this state until the next ChannelClose,
  // then any subsequent messages must be blocked.
  Preempted = 4,
  // A Bereft channel is one for which there is no longer a corresponding active channel known to
  // the peer. This state can be reached in two ways:
  // 1. A channel open request is initiated internally and rejected by the local peer.
  // 2. A channel is first preempted, then a ChannelClose is received by the local peer.
  // Messages must not be sent to the peer for channels in this state.
  Bereft = 5,
};

// Sentinel value indicating a channel ID that was previously bound, but then cleared. This is used
// to disambiguate between Pending channels which were never assigned an ID, and Pending channels
// which had their ID cleared because a ChannelOpenFailure message was sent.
constexpr uint32_t channel_id_error = 0xFFFFFFFF;

struct PeerLocalID {
  uint32_t channel_id;
  Peer local_peer;
};

struct InternalChannelInfo {
  std::array<std::optional<uint32_t>, 2> peer_ids;
  std::array<ChannelIDState, 2> peer_states;

  std::array<bool, 2> preempted_closed{};
  Peer owner{};
};

constexpr auto format_as(const InternalChannelInfo& info) {
  fmt::dynamic_format_arg_store<fmt::format_context> args;
  for (auto peer : {Peer::Upstream, Peer::Downstream}) {
    args.push_back(info.owner == peer ? "*" : "");
    args.push_back(info.peer_states[peer]);
    if (info.peer_states[peer] != ChannelIDState::Unbound) {
      args.push_back(":");
      args.push_back(info.peer_ids[peer]);
    } else {
      args.push_back("");
      args.push_back("");
    }
  }
  return fmt::vformat("U{}:{}{}{}|D{}:{}{}{}", args);
}

// Manages channel ID mappings.
// Channel IDs for proxied SSH connections are managed as follows:
//
// Both the downstream and upstream can open channels on the connection via ChannelOpenMsg. When
// doing so, whichever side opens the channel provides their own ID for that channel. Then, if the
// channel is opened successfully, the other side responds with *their* own channel ID for that
// channel. All channel messages after ChannelOpen, including the open response, have a field
// (in our messages, named 'recipient_channel') which contains the peer's channel ID for which the
// message applies. This ID is the one given by the peer itself.
//
// Thus, normally, any given channel can be identified by two separate IDs:
// 1. The ID provided by the downstream, which the upstream uses to send messages to the downstream
// 2. The ID provided by the upstream, which the downstream uses to send messages to the upstream
//
// In our case however, we maintain a third internal channel ID. Because we do not have control over
// the IDs generated by either party, forwarding channel IDs directly could lead to ID conflicts
// in some cases. For example, if we need to open a channel to the upstream ourselves, the
// downstream does not know this, and if it then tries to open another channel, it could generate
// the ID of a channel we have already created (the IDs are usually generated monotonically).
//
// To solve this, we do the following (note this is independent of which peer is the downstream or
// upstream, so we call them Alice and Bob):
// 1. A ChannelOpenMsg received from Alice has its 'sender_channel' field swapped with a
//    newly-generated internal channel ID before it is sent to Bob. The mapping between Alice's
//    sender_channel and ours is stored here, as the original sender_channel is the ID which must
//    be used when messages are ultimately sent back to Alice, regardless of source.
// 2. A ChannelOpenConfirmationMsg sent by Bob to Alice in response contains both sender_channel
//    and recipient_channel fields. The sender_channel here is Bob's new channel ID, and the
//    recipient_channel is *our* internal ID. Before forwarding this message to Alice, we will
//    make the following changes:
//    - The sender_channel (Bob's ID) is stored, and replaced with the recipient_channel (our ID).
//    - The recipient_channel is replaced with Alice's ID, obtained by lookup from our internal ID.
// 3. For any subsequent channel messages (see concept ChannelMsg), it can be assumed that the
//    recipient_channel refers to our internal ID. If the message is to be sent to Bob, the
//    recipient_channel is replaced with Bob's ID, which was tracked in (2). If the message is to
//    be sent to Alice, the recipient_channel is replaced with Alice's ID, which was tracked in (1).
//
// Internal channels keep track of the upstream and downstream channel IDs and whether or not they
// have been "bound" to the internal ID. The ID is only fully released for re-use once a matching
// call to releaseChannelID() has been made for each peer that has called bindChannelID() for the ID.
// Because individual Channel instances only handle messages read from their local peer, not
// messages sent from the remote peer, this allows a Channel to be destroyed when it is done
// handling any reads on the channel (i.e. after reading a ChannelClose message), and still allow
// the opposite peer to respond with their own ChannelClose message to the correct channel ID.
// At the protocol level, the channel is not "closed" until both sides have sent and received a
// ChannelClose message. Only when this happens is the ID released for re-use.
//
class ChannelIDManager : NonCopyable,
                         public StreamInfo::FilterState::Object,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  ChannelIDManager(uint32_t start_id = 0, uint32_t id_limit = DefaultMaxConcurrentChannels)
      : id_alloc_(start_id, start_id + id_limit) {}

  absl::StatusOr<uint32_t> allocateNewChannel(Peer owner);

  // Associates a peer-local channel ID with an internal ID.
  absl::Status bindChannelID(uint32_t internal_id, PeerLocalID peer_local_id, BindMode mode);
  void releaseChannelID(uint32_t internal_id, Peer local_peer);

  std::optional<Peer> owner(uint32_t internal_id);

  // Returns true if it is valid to call preempt() for a given channel ID and local peer, otherwise
  // false. A channel is eligible for preemption by a given peer if it is in the Bound state for
  // that peer, and it is in either the Bound or Unbound states for the opposite peer.
  bool isPreemptable(uint32_t internal_id, Peer local_peer);

  // Changes the peer state for a Bound or HalfBound channel to Preempted, and returns the previous
  // state. The Preempted state has the following effects:
  //
  // 1. Messages are allowed to be sent only until the next ChannelClose or ChannelOpenFailure
  //    message, after which messages are blocked.
  //
  //    It is normally not necessary to check this condition and block messages explicitly; the
  //    protocol always disallows any channel messages to be sent after ChannelClose, so it's not
  //    something that should happen under normal conditions. However, in the case where the channel
  //    is preempted, the remote peer is not privy to the fact that we are breaking the rules (nor
  //    should it be). It may attempt to send its own ChannelClose for any reason, which is fine as
  //    long as it observes the same effects from doing so as it would normally.
  //
  // 2. When the channel is eventually released, its peer state transitions to Bereft, instead of
  //    Released.
  //
  //    This has implications for passthrough channels with two bound peers: if one peer preempts a
  //    channel, then receives a ChannelClose response, it will forward that message to the remote
  //    peer, which will respond with its own ChannelClose. This response from the remote peer must
  //    then be dropped, because the channel has already been fully closed on the local side (the
  //    remote peer is not aware of this). When the remote peer releases the ID, the channel is
  //    freed as usual. Bereft channels are considered the same as Released for purposes of
  //    determining whether to free an internal channel. Preempted channels are, however, not
  //    considered released and will hold the internal channel alive.
  [[nodiscard]]
  ChannelIDState preempt(uint32_t internal_id, Peer local_peer);

  // Updates the recipient channel for the given message in-place from the internal channel ID to
  // the local ID for the destination peer. Returns true if the message should be sent, or (rarely)
  // false if the message should be dropped.
  //
  // NB: Calling this function updates channel state in some cases. Only call this function if you
  // can commit to actually sending the message right away (if it returns true). It is assumed that
  // the dest peer will receive channel messages sequenced in the same order that this function is
  // called for those messages, and channel messages can be sent internally in response to
  // preemption or potentially in other error scenarios.
  // For example: if this function is called and returns true, and then that message is stored to be
  // sent later, this function might be called from somewhere else in a future event loop cycle,
  // and if that message is sent it would be sequenced out of order from the one that was stored
  // previously.
  template <wire::ChannelMsg M>
  absl::StatusOr<bool> processOutgoingChannelMsg(M& msg, Peer dest) {
    return processOutgoingChannelMsgImpl(msg.recipient_channel, msg.msg_type(), dest);
  }
  absl::StatusOr<bool> processOutgoingChannelMsg(wire::ChannelMessage& msg, Peer dest) {
    return msg.visit([this, dest](wire::ChannelMsg auto& msg) {
      return processOutgoingChannelMsg(msg, dest);
    });
  }

  size_t numActiveChannels() const { return internal_channels_.size(); }
  uint32_t nextInternalIdForTest() const { return id_alloc_.peekNext(); }

  // Warning: complete_cb will not be destroyed unless the returned handle is destroyed.
  [[nodiscard]]
  Envoy::Common::CallbackHandlePtr startDrain(Envoy::Event::Dispatcher& dispatcher, std::function<void()> complete_cb);

  std::optional<ChannelIDState> peerState(uint32_t internal_id, Peer peer);

private:
  absl::StatusOr<bool> processOutgoingChannelMsgImpl(wire::field<uint32_t>& recipient_channel,
                                                     wire::SshMessageType msg_type,
                                                     Peer dest);
#ifdef NDEBUG
  absl::flat_hash_map<uint32_t, InternalChannelInfo> internal_channels_;
#else
  std::unordered_map<uint32_t, InternalChannelInfo> internal_channels_;
#endif
  IDAllocator<uint32_t> id_alloc_;
  bool draining_{false};
  std::shared_ptr<Envoy::Common::ThreadSafeCallbackManager> drain_cb_ =
    Envoy::Common::ThreadSafeCallbackManager::create();
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

DECL_BASIC_ENUM_FORMATTER(Envoy::Extensions::NetworkFilters::GenericProxy::Codec::Peer);
DECL_BASIC_ENUM_FORMATTER(Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ChannelIDState);