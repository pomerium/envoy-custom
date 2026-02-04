#include "source/extensions/filters/network/ssh/channel.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

Channel::~Channel() {
  if (callbacks_ != nullptr) {
    callbacks_->cleanup();
  }
};

absl::Status Channel::setChannelCallbacks(ChannelCallbacks& callbacks) {
  callbacks_ = &callbacks;
  return absl::OkStatus();
}

absl::Status PassthroughChannel::readMessage(wire::ChannelMessage&& msg) {
  return callbacks_->sendMessageRemote(std::move(msg));
}

absl::Status ForceCloseChannel::readMessage(wire::ChannelMessage&& msg) {
  return msg.visit(
    [&](wire::ChannelOpenConfirmationMsg&) {
      ENVOY_LOG(debug, "channel {}: closing due to peer preemption", callbacks_->channelId());
      callbacks_->sendMessageLocal(wire::ChannelCloseMsg{
        .recipient_channel = callbacks_->channelId(),
      });
      return absl::OkStatus();
    },
    [&](wire::ChannelOpenFailureMsg&) {
      return absl::OkStatus();
    },
    [](wire::ChannelCloseMsg&) {
      return absl::OkStatus();
    },
    [&](auto& msg) {
      // Ignore any messages received before the reply to our ChannelClose request.
      // Note: The only way to get here is after receiving a ChannelOpenConfirmation.
      ENVOY_LOG(debug, "channel {}: dropping message: {}", callbacks_->channelId(), msg.msg_type());
      return absl::OkStatus();
    });
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec