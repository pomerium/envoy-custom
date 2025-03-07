#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "transport.h"

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
  } else if (authState.channel_mode == ChannelMode::Multiplex) {
    multiplexer_->handleDownstreamToUpstreamMessage(msg);
    return absl::OkStatus();
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

  if (authState.multiplexing_info.mode == MultiplexingMode::Source) {
    multiplexer_->handleUpstreamToDownstreamMessage(msg);
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
      const auto& handOffMsg = ctrl_action.hand_off();
      transport_.authState().hijacked_stream->resetStream();
      transport_.authState().hijacked_stream = nullptr;
      auto newState = transport_.authState().clone();
      newState->handoff_info.handoff_in_progress = true;
      newState->channel_mode = ChannelMode::Handoff;
      newState->multiplexing_info = MultiplexingInfo{
        .mode = MultiplexingMode::Source,
        .transport_callbacks = &transport_,
      };
      if (handOffMsg.has_downstream_channel_info()) {
        newState->handoff_info.channel_info = std::make_unique<pomerium::extensions::ssh::SSHDownstreamChannelInfo>();
        newState->handoff_info.channel_info->MergeFrom(handOffMsg.downstream_channel_info());
      }
      if (handOffMsg.has_downstream_pty_info()) {
        newState->handoff_info.pty_info = std::make_unique<pomerium::extensions::ssh::SSHDownstreamPTYInfo>();
        newState->handoff_info.pty_info->MergeFrom(handOffMsg.downstream_pty_info());
      }
      if (handOffMsg.has_upstream_auth()) {
        newState->username = handOffMsg.upstream_auth().username();
        newState->hostname = handOffMsg.upstream_auth().hostname();
      }
      transport_.initUpstream(std::move(newState));

      break;
    }
    case pomerium::extensions::ssh::SSHChannelControlAction::kDisconnect:
      // TODO
      PANIC("unimplemented");
    case pomerium::extensions::ssh::SSHChannelControlAction::ACTION_NOT_SET:
      break;
    }
    break;
  }
  case pomerium::extensions::ssh::ChannelMessage::MESSAGE_NOT_SET:
    break;
  }
}

void DownstreamConnectionService::beginStream(const AuthState& auth_state, Dispatcher& dispatcher) {
  if (!multiplexer_) {
    multiplexer_ = std::make_shared<SessionMultiplexer>(api_, slot_ptr_, dispatcher);
  }
  multiplexer_->onStreamBegin(auth_state);
}

void UpstreamConnectionService::beginStream(const AuthState& auth_state, Dispatcher& dispatcher) {
  if (!multiplexer_) {
    multiplexer_ = std::make_shared<SessionMultiplexer>(api_, slot_ptr_, dispatcher);
  }
  multiplexer_->onStreamBegin(auth_state);
}
void UpstreamConnectionService::onDisconnect() {
  if (multiplexer_) {
    multiplexer_->onStreamEnd();
  }
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec