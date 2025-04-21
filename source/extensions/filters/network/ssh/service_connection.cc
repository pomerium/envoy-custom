#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/multiplexer.h"
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

absl::Status ConnectionService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(req).status();
}

void DownstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
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

absl::Status DownstreamConnectionService::handleMessage(wire::Message&& msg) {
  const auto& authState = transport_.authState();
  if (authState.channel_mode == ChannelMode::Hijacked) {
    auto& authState = transport_.authState();
    ChannelMessage channel_msg;
    google::protobuf::BytesValue b;
    auto msgData = encodeTo<std::string>(msg);
    if (!msgData.ok()) {
      return absl::InvalidArgumentError(fmt::format("received invalid message: {}", msgData.status()));
    }
    *b.mutable_value() = *msgData;
    *channel_msg.mutable_raw_bytes() = b;
    if (auto s = authState.hijacked_stream.lock(); s) {
      s->sendMessage(channel_msg, false);
    } else {
      return absl::CancelledError("connection closed");
    }
    return absl::OkStatus();
  }
  switch (authState.multiplexing_info.multiplex_mode) {
  case MultiplexMode::Mirror:
    return mirror_multiplexer_->handleDownstreamToUpstreamMessage(msg);
  case MultiplexMode::Source:
    if (auto r = source_multiplexer_->handleDownstreamToUpstreamMessage(msg); !r.ok()) {
      return r;
    }
    // keep going
    break;
  default:
    break;
  }

  return msg.visit(
    [&](wire::ChannelOpenMsg& msg) {
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::ChannelMsg auto& msg) {
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
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
      auto newState = transport_.authState().clone();
      switch (handOffMsg->upstream_auth().target_case()) {
      case pomerium::extensions::ssh::AllowResponse::kUpstream: {
        newState->handoff_info.handoff_in_progress = true;
        newState->channel_mode = ChannelMode::Handoff;
        if (handOffMsg->upstream_auth().upstream().allow_mirror_connections()) {
          newState->multiplexing_info.multiplex_mode = MultiplexMode::Source;
        }
        if (handOffMsg->has_downstream_channel_info()) {
          newState->handoff_info.channel_info.reset(handOffMsg->release_downstream_channel_info());
        }
        if (handOffMsg->has_downstream_pty_info()) {
          newState->handoff_info.pty_info.reset(handOffMsg->release_downstream_pty_info());
        }
        if (handOffMsg->has_upstream_auth()) {
          newState->allow_response.reset(handOffMsg->release_upstream_auth());
        }
        transport_.initUpstream(std::move(newState));
        return absl::OkStatus();
      }
      case pomerium::extensions::ssh::AllowResponse::kMirrorSession: {
        const auto& allowResp = handOffMsg->upstream_auth();
        const auto& mirror = allowResp.mirror_session();
        newState->multiplexing_info.multiplex_mode = MultiplexMode::Mirror;
        newState->channel_mode = ChannelMode::Mirror;
        if (handOffMsg->has_downstream_channel_info()) {
          newState->multiplexing_info.downstream_channel_id = handOffMsg->downstream_channel_info().downstream_channel_id();
        } else {
          return absl::InternalError("received invalid channel message: missing downstream_channel_info");
        }
        switch (mirror.mode()) {
        case pomerium::extensions::ssh::MirrorSessionTarget_Mode_ReadOnly:
          newState->multiplexing_info.rw_mode = ReadWriteMode::ReadOnly;
          break;
        case pomerium::extensions::ssh::MirrorSessionTarget_Mode_ReadWrite:
          newState->multiplexing_info.rw_mode = ReadWriteMode::ReadWrite;
          break;
        default:
          return absl::InternalError(fmt::format("received invalid channel message: unknown mode: {}",
                                                 static_cast<int>(mirror.mode())));
        }
        newState->multiplexing_info.source_stream_id = mirror.source_id();
        transport_.initUpstream(std::move(newState));
        return absl::OkStatus();
      }
      default:
        return absl::InternalError(fmt::format("received invalid channel message: unknown target: {}",
                                               static_cast<int>(handOffMsg->upstream_auth().target_case())));
      }
    }
    case pomerium::extensions::ssh::SSHChannelControlAction::kDisconnect:
      ENVOY_LOG(debug, "received disconnect channel message");
      // TODO: pass through status
      return absl::CancelledError(ctrl_action.disconnect().description());
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

absl::Status DownstreamConnectionService::onStreamBegin(const AuthState& auth_state, Dispatcher& dispatcher) {
  switch (auth_state.multiplexing_info.multiplex_mode) {
  case Codec::MultiplexMode::Mirror:
    if (!mirror_multiplexer_) {
      mirror_multiplexer_ = std::make_shared<MirrorSessionMultiplexer>(api_, transport_, slot_ptr_, dispatcher);
      if (auto stat = mirror_multiplexer_->onStreamBegin(auth_state); !stat.ok()) {
        return stat;
      }
    }
    break;
  case Codec::MultiplexMode::Source:
    if (!source_multiplexer_) {
      source_multiplexer_ = std::make_shared<SourceDownstreamSessionMultiplexer>();
      (*slot_ptr_)->awaitSession(auth_state.stream_id, source_multiplexer_);
    }
    break;
  default:
    break;
  }
  return absl::OkStatus();
}

void DownstreamConnectionService::onStreamEnd() {
  if (source_multiplexer_) {
    source_multiplexer_->onStreamEnd();
    source_multiplexer_ = nullptr;
  }
  if (mirror_multiplexer_) {
    mirror_multiplexer_->onStreamEnd("session ended");
    mirror_multiplexer_ = nullptr;
  }
}

void UpstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
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
  const auto& authState = transport_.authState();

  if (authState.multiplexing_info.multiplex_mode == MultiplexMode::Source) {
    if (auto stat = source_multiplexer_->handleUpstreamToDownstreamMessage(msg); !stat.ok()) {
      return stat;
    }
  }

  return msg.visit(
    [&](wire::ChannelMsg auto& msg) {
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

absl::Status UpstreamConnectionService::onStreamBegin(const AuthState& auth_state, Dispatcher& dispatcher) {
  if (!source_multiplexer_) {
    source_multiplexer_ = std::make_shared<SourceUpstreamSessionMultiplexer>(api_, transport_, slot_ptr_, dispatcher);
  }
  if (auto stat = source_multiplexer_->onStreamBegin(auth_state); !stat.ok()) {
    return stat;
  }
  return absl::OkStatus();
}

void UpstreamConnectionService::onStreamEnd() {
  if (source_multiplexer_) {
    source_multiplexer_->onStreamEnd();
    source_multiplexer_ = nullptr;
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec