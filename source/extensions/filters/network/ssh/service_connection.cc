#include "source/extensions/filters/network/ssh/service_connection.h"
#include "messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

decltype(ConnectionService::channelTypes) ConnectionService::channelTypes = {};

ConnectionService::ConnectionService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  (void)transport_;
  (void)api_;
}

std::string ConnectionService::name() const { return "ssh-connection"; }

absl::Status ConnectionService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
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
      return transport_.sendMessageToConnection(confirmation).status();
    } else {
      ChannelOpenFailureMsg failure;
      failure.recipient_channel = channelOpenMsg.sender_channel;
      failure.reason_code = SSH2_OPEN_UNKNOWN_CHANNEL_TYPE;
      failure.description = "unknown channel type";
      return transport_.sendMessageToConnection(failure).status();
    }
    break;
  }
  case SshMessageType::ChannelRequest: {
    auto channelRequestMsg = msg.unwrap<ChannelRequestMsg>();
    if (active_channels_.contains(channelRequestMsg.channel)) {
      return active_channels_[channelRequestMsg.channel]->handleRequest(channelRequestMsg);
    }
    break;
  }
  default:
    break;
  }
  return absl::OkStatus();
}

void ConnectionService::registerMessageHandlers(MessageDispatcher& dispatcher) {
  dispatcher.registerHandler(SshMessageType::ChannelOpen, this);
  dispatcher.registerHandler(SshMessageType::ChannelRequest, this);
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec