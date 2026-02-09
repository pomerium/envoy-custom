#pragma once

#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#pragma clang unsafe_buffer_usage begin
#include "envoy/stats/scope.h"
#include "envoy/common/callback.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ChannelStatsProvider {
public:
  virtual ~ChannelStatsProvider() = default;

  // Called by the connection service periodically when collecting aggregated channel stats.
  virtual void populateChannelStats(pomerium::extensions::ssh::ChannelStats&) const PURE;
};

class ChannelCallbacks {
public:
  virtual ~ChannelCallbacks() = default;

  // Sends a message to the local peer. For channel messages (see wire::ChannelMsg), the
  // recipient_channel field does not need to be set. It will be set to the current internal
  // channel ID automatically.
  virtual void sendMessageLocal(wire::Message&& msg) PURE;

  // Sends a message to the remote peer. For channel messages (see wire::ChannelMsg), the
  // recipient_channel field does not need to be set. It will be set to the current internal
  // channel ID automatically.
  virtual absl::Status sendMessageRemote(wire::Message&& msg) PURE;

  // Returns the channel's internal ID.
  virtual uint32_t channelId() const PURE;

  // Base stats scope
  virtual Stats::Scope& scope() const PURE;

  // Sets the stats provider for this channel (usually the channel itself). If set, the stats
  // provider's populateChannelStats() method will be invoked at regular intervals to obtain stats
  // for the channel.
  virtual void setStatsProvider(ChannelStatsProvider& stats_provider) PURE;

  // Adds an interrupt callback to be invoked before a channel is closed to perform graceful
  // shutdown in the event of an unexpected disconnect or other non-connection-fatal issue.
  // These callbacks can be invoked using runInterruptCallbacks(). The returned handle can be
  // deleted to remove the callback.
  [[nodiscard]]
  virtual Common::CallbackHandlePtr addInterruptCallback(std::function<void(absl::Status, TransportCallbacks&)> cb) PURE;

  // Invokes all previously added interrupt callbacks, then clears the interrupt callback list.
  // Deleting a callback handle obtained from addInterruptCallbacks after calling this function
  // is a no-op; it is safe to let the callback handles go out of scope normally.
  // This function can be invoked manually from a Channel implementation. It may also be invoked
  // by the ConnectionService itself. Either way, any added callbacks are only invoked once.
  virtual void runInterruptCallbacks(absl::Status err) PURE;

  // Terminates the connection with an error. This will send an immediate Disconnect message.
  virtual void terminate(absl::Status err) PURE;

private:
  friend class Channel;
  virtual void cleanup() PURE;
};

class ChannelEventCallbacks {
public:
  virtual ~ChannelEventCallbacks() = default;
  virtual void sendChannelEvent(const pomerium::extensions::ssh::ChannelEvent& ev) PURE;
};

// Channel handles the read path for a single peer (upstream or downstream) for messages on a
// SSH channel. For channels known to both the upstream server and downstream client, two Channel
// objects will exist: one managed by the upstream ConnectionService, and one by the downstream
// ConnectionService. The channel objects do not necessarily need to have the same implementation.
//
// The peer which this channel is handling the read path for is referred to as the local peer. The
// opposite peer is referred to as the remote peer. For example, if this channel is managed by
// the downstream ConnectionService, the local peer is the downstream and the remote peer is the
// upstream.
class Channel {
public:
  virtual ~Channel();
  virtual absl::Status setChannelCallbacks(ChannelCallbacks& callbacks);

  // Handles a channel message (see concept ChannelMsg) read from the local peer, to be sent to
  // the remote peer.
  virtual absl::Status readMessage(wire::ChannelMessage&& msg) PURE;

protected:
  ChannelCallbacks* callbacks_{};
};

class PassthroughChannel : public Channel {
public:
  PassthroughChannel() = default;

  absl::Status readMessage(wire::ChannelMessage&& msg) override;
};

class ForceCloseChannel : public Channel, public Logger::Loggable<Logger::Id::filter> {
public:
  ForceCloseChannel() = default;

  absl::Status readMessage(wire::ChannelMessage&& msg) override;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec