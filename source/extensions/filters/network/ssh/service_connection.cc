#include "source/extensions/filters/network/ssh/service_connection.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

decltype(ConnectionService::channelTypes) ConnectionService::channelTypes = {};

ConnectionService::ConnectionService(ServerTransportCallbacks* callbacks, Api::Api& api)
    : callbacks_(callbacks), api_(api) {
  (void)callbacks_;
  (void)api_;
}

std::string ConnectionService::name() const { return "ssh-connection"; }

bool ConnectionService::acceptsMessage(SshMessageType msgType) const {
  auto msgNum = static_cast<uint8_t>(msgType);
  return msgNum >= 80 && msgNum <= 127;
}

error ConnectionService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::GlobalRequest:
    break;
  case SshMessageType::RequestSuccess:
    break;
  case SshMessageType::RequestFailure:
    break;
  case SshMessageType::ChannelOpen: {
    auto channelOpenMsg = msg.unwrap<ChannelOpenMsg>();
    auto newId = ++SessionIdCounter;
    if (channelTypes.contains(channelOpenMsg.channel_type)) {
      active_channels_[newId] = channelTypes[channelOpenMsg.channel_type](newId);
      ChannelOpenConfirmationMsg confirmation;
      confirmation.sender_channel = newId;
      confirmation.recipient_channel = channelOpenMsg.sender_channel;
      confirmation.initial_window_size = channelOpenMsg.initial_window_size;
      confirmation.max_packet_size = channelOpenMsg.max_packet_size;
      return callbacks_->downstream().sendMessage(confirmation);
    } else {
      ChannelOpenFailureMsg failure;
      failure.recipient_channel = channelOpenMsg.sender_channel;
      failure.reason_code = SSH2_OPEN_UNKNOWN_CHANNEL_TYPE;
      failure.description = "unknown channel type";
      return callbacks_->downstream().sendMessage(failure);
    }
    break;
  }
  case SshMessageType::ChannelOpenConfirmation:
    break;
  case SshMessageType::ChannelOpenFailure:
    break;
  case SshMessageType::ChannelWindowAdjust:
    break;
  case SshMessageType::ChannelData:
    break;
  case SshMessageType::ChannelExtendedData:
    break;
  case SshMessageType::ChannelEOF:
    break;
  case SshMessageType::ChannelClose:
    break;
  case SshMessageType::ChannelRequest: {
    auto channelRequestMsg = msg.unwrap<ChannelRequestMsg>();
    if (active_channels_.contains(channelRequestMsg.channel)) {
      return active_channels_[channelRequestMsg.channel]->handleRequest(channelRequestMsg);
    }
    break;
  }
  case SshMessageType::ChannelSuccess:
    break;
  case SshMessageType::ChannelFailure:
    break;
  default:
    break;
  }
  return std::nullopt;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec