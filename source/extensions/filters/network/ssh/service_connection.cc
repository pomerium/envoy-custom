#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

decltype(ConnectionService::channelTypes) ConnectionService::channelTypes = {};

ConnectionService::ConnectionService(TransportCallbacks& callbacks, Api::Api& api, bool is_server)
    : transport_(callbacks), api_(api), is_server_(is_server) {
  (void)transport_;
  (void)api_;
}

absl::Status ConnectionService::handleMessage(AnyMsg&& msg) {
  auto streamId = transport_.authState().stream_id;
  switch (msg.msgtype) {
  case SshMessageType::ChannelOpen:
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelOpenMsg>()));
    break;
  case SshMessageType::ChannelOpenConfirmation:
    transport_.forward(std::make_unique<SSHResponseCommonFrame>(
        streamId, msg.unwrap<ChannelOpenConfirmationMsg>()));
    break;
  case SshMessageType::ChannelOpenFailure:
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelOpenFailureMsg>()));
    break;
  case SshMessageType::ChannelWindowAdjust: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelWindowAdjustMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelWindowAdjustMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelData: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelDataMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelDataMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelExtendedData: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelExtendedDataMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelExtendedDataMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelEOF: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelEOFMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelEOFMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelClose: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelCloseMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelCloseMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelRequest: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelRequestMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelRequestMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelSuccess: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelSuccessMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelSuccessMsg>()));
    }
    break;
  }
  case SshMessageType::ChannelFailure: {
    if (is_server_) {
      transport_.forward(
          std::make_unique<SSHRequestCommonFrame>(streamId, msg.unwrap<ChannelFailureMsg>()));
    } else {
      transport_.forward(
          std::make_unique<SSHResponseCommonFrame>(streamId, msg.unwrap<ChannelFailureMsg>()));
    }
    break;
  }
  default:
    break;
  }
  return absl::OkStatus();

  switch (msg.msgtype) {
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

void ConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
  dispatcher.registerHandler(SshMessageType::ChannelOpen, this);
  dispatcher.registerHandler(SshMessageType::ChannelOpenConfirmation, this);
  dispatcher.registerHandler(SshMessageType::ChannelOpenFailure, this);
  dispatcher.registerHandler(SshMessageType::ChannelWindowAdjust, this);
  dispatcher.registerHandler(SshMessageType::ChannelData, this);
  dispatcher.registerHandler(SshMessageType::ChannelExtendedData, this);
  dispatcher.registerHandler(SshMessageType::ChannelEOF, this);
  dispatcher.registerHandler(SshMessageType::ChannelClose, this);
  dispatcher.registerHandler(SshMessageType::ChannelRequest, this);
  dispatcher.registerHandler(SshMessageType::ChannelSuccess, this);
  dispatcher.registerHandler(SshMessageType::ChannelFailure, this);
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec