#pragma once

#include "source/extensions/filters/network/ssh/wire/messages.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ChannelCallbacks {
public:
  virtual ~ChannelCallbacks() = default;
  virtual absl::Status sendMessageToConnection(wire::Message&& msg) PURE;
  virtual void passthrough(wire::Message&& msg) PURE;
  virtual uint32_t channelId() const PURE;

private:
  friend class Channel;
  virtual void cleanup() PURE;
};

// Channel handles the read path for a single peer (upstream or downstream) for messages on a
// SSH channel. For channels known to both the upstream server and downstream client, two Channel
// object will exist: one managed by the upstream ConnectionService, and one by the downstream.
// The channel objects do not necessarily need to have the same implementation.
class Channel {
public:
  virtual ~Channel() {
    if (callbacks_ != nullptr) {
      callbacks_->cleanup();
    }
  };
  virtual void setChannelCallbacks(ChannelCallbacks& callbacks) {
    callbacks_ = &callbacks;
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
    callbacks_->passthrough(std::move(msg));
    return absl::OkStatus();
  }

  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&& msg) override {
    callbacks_->passthrough(std::move(msg));
    return absl::OkStatus();
  }

  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&& msg) override {
    callbacks_->passthrough(std::move(msg));
    return absl::OkStatus();
  }
};

class ChannelEventCallbacks {
public:
  virtual ~ChannelEventCallbacks() = default;
  virtual void sendChannelEvent(const pomerium::extensions::ssh::ChannelEvent& ev) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec