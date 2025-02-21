#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "buffer.h"
#include "messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ConnectionService::ConnectionService(TransportCallbacks& callbacks, Api::Api& api, AccessLog::AccessLogFileSharedPtr access_log)
    : transport_(callbacks), api_(api), access_log_(access_log) {
  (void)api_;
}

void DownstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
  dispatcher.registerHandler(SshMessageType::ChannelOpen, this);
  dispatcher.registerHandler(SshMessageType::ChannelWindowAdjust, this);
  dispatcher.registerHandler(SshMessageType::ChannelData, this);
  dispatcher.registerHandler(SshMessageType::ChannelExtendedData, this);
  dispatcher.registerHandler(SshMessageType::ChannelEOF, this);
  dispatcher.registerHandler(SshMessageType::ChannelClose, this);
  dispatcher.registerHandler(SshMessageType::ChannelRequest, this);
  dispatcher.registerHandler(SshMessageType::ChannelSuccess, this);
  dispatcher.registerHandler(SshMessageType::ChannelFailure, this);
}

absl::Status DownstreamConnectionService::handleMessage(SshMsg&& msg) {
  const auto& authState = transport_.authState();
  if (authState.channel_mode == ChannelMode::Hijacked) {
    auto& authState = transport_.authState();
    ChannelMessage channel_msg;
    google::protobuf::BytesValue b;
    *b.mutable_value() = msg.toString();
    *channel_msg.mutable_raw_bytes() = b;
    authState.hijacked_stream->sendMessage(channel_msg, false);
    return absl::OkStatus();
  }
  auto streamId = authState.stream_id;
  switch (msg.msg_type()) {
  case SshMessageType::ChannelOpen: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelOpenMsg&&>(msg)));
    break;
  }
  case SshMessageType::ChannelWindowAdjust: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelWindowAdjustMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelData: {
    const auto& dataMsg = dynamic_cast<const ChannelDataMsg&>(msg);
    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      frame.mutable_raw_data()->resize(dataMsg.data->size());
      memcpy(frame.mutable_raw_data()->data(), dataMsg.data->data(), dataMsg.data->size());
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      write_opt<LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelDataMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelExtendedData: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelExtendedDataMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelEOF: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelEOFMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelClose: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelCloseMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelRequest: {
    const auto& reqMsg = dynamic_cast<const ChannelRequestMsg&>(msg);

    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      pomerium::extensions::ssh::RecordingFrame::ChannelRequest channelReqFrame;
      channelReqFrame.set_request_type(reqMsg.request_type);
      auto subMsgData = encodeToBytes(reqMsg.msg);

      channelReqFrame.mutable_request()->resize(subMsgData.size());
      memcpy(channelReqFrame.mutable_request()->data(), subMsgData.data(), subMsgData.size());
      *frame.mutable_channel_request() = channelReqFrame;
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      write_opt<LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelRequestMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelSuccess: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelSuccessMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelFailure: {
    transport_.forward(
        std::make_unique<SSHRequestCommonFrame>(streamId, dynamic_cast<ChannelFailureMsg&&>(msg)));

    break;
  }
  default:
    break;
  }
  return absl::OkStatus();
}

void UpstreamConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
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
}

absl::Status UpstreamConnectionService::handleMessage(SshMsg&& msg) {
  const auto& authState = transport_.authState();
  auto streamId = authState.stream_id;
  switch (msg.msg_type()) {
  case SshMessageType::ChannelOpenConfirmation: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelOpenConfirmationMsg&&>(msg)));
    break;
  }
  case SshMessageType::ChannelOpenFailure: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelOpenFailureMsg&&>(msg)));
    break;
  }
  case SshMessageType::ChannelWindowAdjust: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelWindowAdjustMsg&&>(msg)));
    break;
  }
  case SshMessageType::ChannelData: {
    const auto& dataMsg = dynamic_cast<const ChannelDataMsg&>(msg);
    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      frame.mutable_raw_data()->resize(dataMsg.data->size());
      memcpy(frame.mutable_raw_data()->data(), dataMsg.data->data(), dataMsg.data->size());
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      write_opt<LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelDataMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelExtendedData: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelExtendedDataMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelEOF: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelEOFMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelClose: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelCloseMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelRequest: {
    const auto& reqMsg = dynamic_cast<const ChannelRequestMsg&>(msg);

    if (access_log_) {
      pomerium::extensions::ssh::RecordingFrame frame;
      frame.mutable_timestamp()->MergeFrom(
          Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::GetCurrentTimeNanos()));
      pomerium::extensions::ssh::RecordingFrame::ChannelRequest channelReqFrame;
      channelReqFrame.set_request_type(reqMsg.request_type);
      auto subMsgData = encodeToBytes(reqMsg.msg);
      channelReqFrame.mutable_request()->resize(subMsgData.size());
      memcpy(channelReqFrame.mutable_request()->data(), subMsgData.data(), subMsgData.size());
      *frame.mutable_channel_request() = channelReqFrame;
      Envoy::Buffer::OwnedImpl tmp;
      auto str = frame.SerializeAsString();
      write_opt<LengthPrefixed>(tmp, str);
      access_log_->write(tmp.toString());
      tmp.drain(tmp.length());
    }
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelRequestMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelSuccess: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelSuccessMsg&&>(msg)));

    break;
  }
  case SshMessageType::ChannelFailure: {
    transport_.forward(
        std::make_unique<SSHResponseCommonFrame>(streamId, dynamic_cast<ChannelFailureMsg&&>(msg)));

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
    auto _ = transport_.sendMessageToConnection(AnyMsg::fromString(message->raw_bytes().value()));
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