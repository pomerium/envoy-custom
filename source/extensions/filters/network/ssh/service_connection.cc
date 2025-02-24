#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ConnectionService::ConnectionService(TransportCallbacks& callbacks, Api::Api& api, AccessLog::AccessLogFileSharedPtr access_log)
    : transport_(callbacks), api_(api), access_log_(access_log) {
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

absl::Status DownstreamConnectionService::handleMessage(wire::SshMsg&& msg) {
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
  auto streamId = authState.stream_id;
  switch (msg.msg_type()) {
  case wire::SshMessageType::ChannelOpen: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelOpenMsg&&>(msg)));
    break;
  }
  case wire::SshMessageType::ChannelWindowAdjust: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelWindowAdjustMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelData: {
    const auto& dataMsg = dynamic_cast<const wire::ChannelDataMsg&>(msg);
    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      frame.mutable_raw_data()->resize(dataMsg.data->size());
      memcpy(frame.mutable_raw_data()->data(), dataMsg.data->data(), dataMsg.data->size());
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      wire::write_opt<wire::LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelDataMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelExtendedData: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelExtendedDataMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelEOF: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelEOFMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelClose: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelCloseMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelRequest: {
    const auto& reqMsg = dynamic_cast<const wire::ChannelRequestMsg&>(msg);

    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      pomerium::extensions::ssh::RecordingFrame::ChannelRequest channelReqFrame;
      channelReqFrame.set_request_type(reqMsg.request_type);
      auto subMsgData = wire::encodeTo<bytes>(reqMsg.msg);
      if (!subMsgData.ok()) {
        return subMsgData.status();
      }

      channelReqFrame.mutable_request()->resize(subMsgData->size());
      memcpy(channelReqFrame.mutable_request()->data(), subMsgData->data(), subMsgData->size());
      *frame.mutable_channel_request() = channelReqFrame;
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      wire::write_opt<wire::LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelRequestMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelSuccess: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelSuccessMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelFailure: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<wire::ChannelFailureMsg&&>(msg)));

    break;
  }
  default:
    break;
  }
  return absl::OkStatus();
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

absl::Status UpstreamConnectionService::handleMessage(wire::SshMsg&& msg) {
  const auto& authState = transport_.authState();
  auto streamId = authState.stream_id;
  switch (msg.msg_type()) {
  case wire::SshMessageType::ChannelOpenConfirmation: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelOpenConfirmationMsg&&>(msg)));
    break;
  }
  case wire::SshMessageType::ChannelOpenFailure: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelOpenFailureMsg&&>(msg)));
    break;
  }
  case wire::SshMessageType::ChannelWindowAdjust: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelWindowAdjustMsg&&>(msg)));
    break;
  }
  case wire::SshMessageType::ChannelData: {
    const auto& dataMsg = dynamic_cast<const wire::ChannelDataMsg&>(msg);
    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      frame.mutable_raw_data()->resize(dataMsg.data->size());
      memcpy(frame.mutable_raw_data()->data(), dataMsg.data->data(), dataMsg.data->size());
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      wire::write_opt<wire::LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelDataMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelExtendedData: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelExtendedDataMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelEOF: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelEOFMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelClose: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelCloseMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelRequest: {
    const auto& reqMsg = dynamic_cast<const wire::ChannelRequestMsg&>(msg);

    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      pomerium::extensions::ssh::RecordingFrame::ChannelRequest channelReqFrame;
      channelReqFrame.set_request_type(reqMsg.request_type);
      auto subMsgData = encodeTo<bytes>(reqMsg.msg);
      if (!subMsgData.ok()) {
        return subMsgData.status();
      }
      channelReqFrame.mutable_request()->resize(subMsgData->size());
      memcpy(channelReqFrame.mutable_request()->data(), subMsgData->data(), subMsgData->size());
      *frame.mutable_channel_request() = channelReqFrame;
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      wire::write_opt<wire::LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelRequestMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelSuccess: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelSuccessMsg&&>(msg)));

    break;
  }
  case wire::SshMessageType::ChannelFailure: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<wire::ChannelFailureMsg&&>(msg)));

    break;
  }
  default:
    break;
  }
  return absl::OkStatus();
}

void DownstreamConnectionService::onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) {
  switch (message->message_case()) {
  case pomerium::extensions::ssh::ChannelMessage::kRawBytes: {
    auto anyMsg = wire::AnyMsg::fromString(message->raw_bytes().value());
    if (!anyMsg.ok()) {
      ENVOY_LOG(error, "received invalid channel message");
      return; // TODO: wire up status here
    }
    auto _ = transport_.sendMessageToConnection(*anyMsg);
    break;
  }
  case pomerium::extensions::ssh::ChannelMessage::kChannelControl: {
    pomerium::extensions::ssh::SSHChannelControlAction ctrl_action;
    message->channel_control().control_action().UnpackTo(&ctrl_action);
    switch (ctrl_action.action_case()) {
    case pomerium::extensions::ssh::SSHChannelControlAction::kHandOff: {
      const auto& handOffMsg = ctrl_action.hand_off();
      transport_.authState().hijacked_stream->resetStream();
      transport_.authState().hijacked_stream = nullptr;
      auto newState = transport_.authState().clone();
      newState->handoff_info.handoff_in_progress = true;
      newState->channel_mode = ChannelMode::Handoff;
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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec