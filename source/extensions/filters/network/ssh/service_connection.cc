#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
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

void DownstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
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
    auto msgData = msg.encodeTo<std::string>();
    if (!msgData.ok()) {
      return absl::InvalidArgumentError("received invalid message");
    }
    *b.mutable_value() = *msgData;
    *channel_msg.mutable_raw_bytes() = b;
    authState.hijacked_stream->sendMessage(channel_msg, false);
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

  auto streamId = authState.stream_id;
  return msg.visit(
    [&](wire::ChannelOpenMsg& msg) {
      transport_.forward(std::make_unique<SSHRequestCommonFrame>(streamId, std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::ChannelMsg auto& msg) {
      transport_.forward(std::make_unique<SSHRequestCommonFrame>(streamId, std::move(msg)));
      return absl::OkStatus();
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

void UpstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
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
  auto streamId = authState.stream_id;

  if (authState.multiplexing_info.multiplex_mode == MultiplexMode::Source) {
    if (auto r = source_multiplexer_->handleUpstreamToDownstreamMessage(msg); !r.ok()) {
      return r;
    }
  }

  return msg.visit(
    [&](wire::ChannelMsg auto& msg) {
      transport_.forward(std::make_unique<SSHResponseCommonFrame>(streamId, std::move(msg)));
      return absl::OkStatus();
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

void DownstreamConnectionService::onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& msg) { // NOLINT
  switch (msg->message_case()) {
  case pomerium::extensions::ssh::ChannelMessage::kRawBytes: {
    auto anyMsg = wire::Message::fromString(msg->raw_bytes().value());
    if (!anyMsg.ok()) {
      ENVOY_LOG(error, "received invalid channel message");
      return; // TODO: wire up status here
    }
    auto _ = transport_.sendMessageToConnection(*anyMsg);
    break;
  }
  case pomerium::extensions::ssh::ChannelMessage::kChannelControl: {
    pomerium::extensions::ssh::SSHChannelControlAction ctrl_action;
    msg->channel_control().control_action().UnpackTo(&ctrl_action);
    switch (ctrl_action.action_case()) {
    case pomerium::extensions::ssh::SSHChannelControlAction::kHandOff: {
      auto* handOffMsg = ctrl_action.mutable_hand_off();
      transport_.authState().hijacked_stream->resetStream();
      transport_.authState().hijacked_stream = nullptr;
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
      } break;
      case pomerium::extensions::ssh::AllowResponse::kMirrorSession: {
        const auto& allowResp = handOffMsg->upstream_auth();
        const auto& mirror = allowResp.mirror_session();
        newState->multiplexing_info.multiplex_mode = MultiplexMode::Mirror;
        newState->channel_mode = ChannelMode::Mirror;
        if (handOffMsg->has_downstream_channel_info()) {
          newState->multiplexing_info.downstream_channel_id = handOffMsg->downstream_channel_info().downstream_channel_id();
        } else {
          ENVOY_LOG(error, "received invalid channel message: missing downstream_channel_info");
          return; // TODO: wire up status here
        }
        switch (mirror.mode()) {
        case pomerium::extensions::ssh::MirrorSessionTarget_Mode_ReadOnly:
          newState->multiplexing_info.rw_mode = ReadWriteMode::ReadOnly;
          break;
        case pomerium::extensions::ssh::MirrorSessionTarget_Mode_ReadWrite:
          newState->multiplexing_info.rw_mode = ReadWriteMode::ReadWrite;
          break;
        default:
          // return absl::InvalidArgumentError("unknown mode");
          return;
        }
        newState->multiplexing_info.source_stream_id = mirror.source_id();
        transport_.initUpstream(std::move(newState));
      } break;
      default:
        ENVOY_LOG(error, "received invalid channel message");
        return; // TODO: wire up status here
      }
    } break;
    case pomerium::extensions::ssh::SSHChannelControlAction::kDisconnect: {
      const auto& disconnectMsg = ctrl_action.disconnect();
      wire::DisconnectMsg msg;
      msg.reason_code = disconnectMsg.reason_code();
      msg.description = disconnectMsg.description();
      (void)transport_.sendMessageToConnection(msg); // TODO
    } break;
    case pomerium::extensions::ssh::SSHChannelControlAction::ACTION_NOT_SET:
      break;
    }
  } break;
  case pomerium::extensions::ssh::ChannelMessage::MESSAGE_NOT_SET:
    break;
  }
}

void DownstreamConnectionService::onStreamBegin(const AuthState& auth_state, Dispatcher& dispatcher) {
  switch (auth_state.multiplexing_info.multiplex_mode) {
  case Codec::MultiplexMode::Mirror:
    if (!mirror_multiplexer_) {
      mirror_multiplexer_ = std::make_shared<MirrorSessionMultiplexer>(api_, transport_, slot_ptr_, dispatcher);
      mirror_multiplexer_->onStreamBegin(auth_state);
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
}

void DownstreamConnectionService::onStreamEnd() {
  if (source_multiplexer_) {
    source_multiplexer_->onStreamEnd();
    source_multiplexer_ = nullptr;
  }
  if (mirror_multiplexer_) {
    mirror_multiplexer_->onStreamEnd();
    mirror_multiplexer_ = nullptr;
  }
}
void UpstreamConnectionService::onStreamBegin(const AuthState& auth_state, Dispatcher& dispatcher) {
  if (!source_multiplexer_) {
    source_multiplexer_ = std::make_shared<SourceUpstreamSessionMultiplexer>(api_, transport_, slot_ptr_, dispatcher);
  }
  source_multiplexer_->onStreamBegin(auth_state);
}

void UpstreamConnectionService::onStreamEnd() {
  if (source_multiplexer_) {
    source_multiplexer_->onStreamEnd();
    source_multiplexer_ = nullptr;
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec