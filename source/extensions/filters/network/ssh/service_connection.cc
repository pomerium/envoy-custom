#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ConnectionService::ConnectionService(
  TransportCallbacks& callbacks,
  Api::Api& api)
    : transport_(callbacks),
      api_(api) {
  (void)api_;
}

void DownstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  msg_dispatcher_ = dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpen, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelWindowAdjust, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelData, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelExtendedData, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelEOF, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelClose, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelFailure, this);
}

absl::Status DownstreamConnectionService::sendToHijackedStream(wire::Message&& msg) {
  ChannelMessage channel_msg;
  google::protobuf::BytesValue b;
  auto msgData = encodeTo<std::string>(msg);
  if (!msgData.ok()) {
    return absl::InvalidArgumentError(fmt::format("received invalid message: {}", msgData.status()));
  }
  *b.mutable_value() = *msgData;
  *channel_msg.mutable_raw_bytes() = b;
  if (auto s = transport_.authState().hijacked_stream.lock(); s) {
    s->sendMessage(channel_msg, false);
  } else {
    return absl::CancelledError("connection closed");
  }
  return absl::OkStatus();
}

absl::Status DownstreamConnectionService::sendToExternalChannel(uint32_t channel_id, wire::Message&& msg) {
  external_channels_[channel_id]->readMessage(std::move(msg));
  return absl::OkStatus();
}

absl::Status DownstreamConnectionService::handleMessage(wire::Message&& msg) {
  auto& authState = transport_.authState();

  return msg.visit(
    [&](wire::ChannelOpenMsg& msg) {
      if (authState.channel_mode == ChannelMode::Hijacked) {
        return sendToHijackedStream(std::move(msg));
      }
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::ChannelMsg auto& msg) {
      if (authState.channel_mode == ChannelMode::Hijacked) {
        if (external_channels_.contains(msg.recipient_channel)) {
          return sendToExternalChannel(msg.recipient_channel, std::move(msg));
        }
        return sendToHijackedStream(std::move(msg));
      }
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [](auto&) {
      return absl::InternalError("unknown message");
    });
}

absl::Status DownstreamConnectionService::onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& msg) {
  switch (msg->message_case()) {
  case pomerium::extensions::ssh::ChannelMessage::kRawBytes: {
    wire::Message anyMsg{};
    auto stat = with_buffer_view(msg->raw_bytes().value(), [&anyMsg](Envoy::Buffer::Instance& buffer) {
      return anyMsg.decode(buffer, buffer.length());
    });
    if (!stat.ok()) {
      return statusf("received invalid channel message: {}", stat.status());
    }
    ENVOY_LOG(debug, "sending channel message to downstream: {}", anyMsg.msg_type());
    return transport_.sendMessageToConnection(std::move(anyMsg)).status();
  }
  case pomerium::extensions::ssh::ChannelMessage::kChannelControl: {
    pomerium::extensions::ssh::SSHChannelControlAction ctrl_action;
    msg->channel_control().control_action().UnpackTo(&ctrl_action);
    switch (ctrl_action.action_case()) {
    case pomerium::extensions::ssh::SSHChannelControlAction::kHandOff: {
      auto* handOffMsg = ctrl_action.mutable_hand_off();
      auto newState = std::make_unique<AuthState>();
      newState->server_version = transport_.authState().server_version;
      newState->stream_id = transport_.authState().stream_id;
      newState->channel_mode = transport_.authState().channel_mode;
      newState->hijacked_stream = transport_.authState().hijacked_stream;
      switch (handOffMsg->upstream_auth().target_case()) {
      case pomerium::extensions::ssh::AllowResponse::kUpstream:
        newState->handoff_info.handoff_in_progress = true;
        newState->channel_mode = ChannelMode::Handoff;
        newState->allow_response.reset(handOffMsg->release_upstream_auth());
        if (handOffMsg->has_downstream_channel_info()) {
          newState->handoff_info.channel_info.reset(handOffMsg->release_downstream_channel_info());
        }
        if (handOffMsg->has_downstream_pty_info()) {
          newState->handoff_info.pty_info.reset(handOffMsg->release_downstream_pty_info());
        }
        transport_.initUpstream(std::move(newState));
        return absl::OkStatus();
      case pomerium::extensions::ssh::AllowResponse::kMirrorSession:
        return absl::UnavailableError("session mirroring feature not available");
      default:
        return absl::InternalError(fmt::format("received invalid channel message: unexpected target: {}",
                                               static_cast<int>(handOffMsg->upstream_auth().target_case())));
      }
    }
    // case pomerium::extensions::ssh::SSHChannelControlAction::kBeginUpstreamTunnel: {
    //   auto* tunnelMsg = ctrl_action.mutable_begin_upstream_tunnel();
    //   auto clusterId = tunnelMsg->cluster_id();

    //   active_stream_tracker_->setStreamIsClusterEndpoint(transport_.streamId(), clusterId, true);
    //   return absl::OkStatus();
    // } break;
    default:
      return absl::InternalError(fmt::format("received invalid channel message: unknown action type: {}",
                                             static_cast<int>(ctrl_action.action_case())));
    }
  }
  default:
    return absl::InternalError(fmt::format("received invalid channel message: unknown message type: {}",
                                           static_cast<int>(msg->message_case())));
  }
}

void DownstreamConnectionService::onStreamBegin(Network::Connection& connection, std::shared_ptr<ActiveStreamCallbacks> callbacks) {
  ASSERT(connection.dispatcher().isThreadSafe());
  test_dispatcher_ = &connection.dispatcher();

  active_stream_handle_ = active_stream_tracker_->onStreamBegin(transport_.streamId(), connection, callbacks);
}

void DownstreamConnectionService::onStreamEnd() {
  active_stream_handle_.reset();
}

absl::Status UpstreamConnectionService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(std::move(req)).status();
}

absl::Status UpstreamConnectionService::onServiceAccepted() {
  return absl::OkStatus();
}

void UpstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  msg_dispatcher_ = &dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpenConfirmation, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpenFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelWindowAdjust, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelData, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelExtendedData, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelEOF, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelClose, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelFailure, this);
}

absl::Status UpstreamConnectionService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ChannelMsg auto& msg) {
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [](auto&) {
      return absl::InternalError("unknown message");
    });
}

// absl::Status UpstreamConnectionService::onStreamBegin(
//   [[maybe_unused]] const AuthState& auth_state,
//   [[maybe_unused]] Dispatcher& dispatcher) {
//   return absl::OkStatus();
// }

// void UpstreamConnectionService::onStreamEnd() {}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec