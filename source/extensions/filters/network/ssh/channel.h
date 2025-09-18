#pragma once

#include "source/extensions/filters/network/ssh/wire/messages.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

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

private:
  friend class Channel;
  virtual void cleanup() PURE;
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
  virtual ~Channel() {
    if (callbacks_ != nullptr) {
      callbacks_->cleanup();
    }
  };
  virtual absl::Status setChannelCallbacks(ChannelCallbacks& callbacks) {
    callbacks_ = &callbacks;
    return absl::OkStatus();
  }

  // Handles a channel message (see concept ChannelMsg) read from the local peer, to be sent to
  // the remote peer.
  virtual absl::Status readMessage(wire::Message&& msg) PURE;

  // Called when the channel is successfully opened. ChannelOpenConfirmation messages are only
  // sent here, not to readMessage().
  virtual absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&&) PURE;

  // Called when the channel failed to open. ChannelOpenFailure messages are only sent here,
  // not to readMessage().
  virtual absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&&) PURE;

protected:
  ChannelCallbacks* callbacks_{};
};

class PassthroughChannel : public Channel {
public:
  PassthroughChannel() = default;

  absl::Status readMessage(wire::Message&& msg) override {
    return callbacks_->sendMessageRemote(std::move(msg));
  }

  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&& msg) override {
    return callbacks_->sendMessageRemote(std::move(msg));
  }

  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&& msg) override {
    return callbacks_->sendMessageRemote(std::move(msg));
  }
};

class ChannelEventCallbacks {
public:
  virtual ~ChannelEventCallbacks() = default;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec