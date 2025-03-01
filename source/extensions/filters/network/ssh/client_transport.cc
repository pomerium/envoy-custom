#include "source/extensions/filters/network/ssh/client_transport.h"

#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshClientCodec::SshClientCodec(Api::Api& api,
                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                               AccessLog::AccessLogFileSharedPtr access_log)
    : TransportBase(api, std::move(config), std::move(access_log)) {
  user_auth_svc_ = std::make_unique<UpstreamUserAuthService>(*this, api);
  user_auth_svc_->registerMessageHandlers(*this);
  connection_svc_ = std::make_unique<UpstreamConnectionService>(*this, api, access_log_);
  connection_svc_->registerMessageHandlers(*this);

  services_[user_auth_svc_->name()] = user_auth_svc_.get();
  services_[connection_svc_->name()] = connection_svc_.get();
}

void SshClientCodec::registerMessageHandlers(MessageDispatcher<wire::SshMsg>& dispatcher) const {
  dispatcher.registerHandler(wire::SshMessageType::ServiceAccept, this);
  dispatcher.registerHandler(wire::SshMessageType::GlobalRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::Ignore, this);
  dispatcher.registerHandler(wire::SshMessageType::Debug, this);
  dispatcher.registerHandler(wire::SshMessageType::Unimplemented, this);
  dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
}

GenericProxy::EncodingResult SshClientCodec::encode(const GenericProxy::StreamFrame& frame,
                                                    GenericProxy::EncodingContext& ctx) {
  switch (dynamic_cast<const SSHStreamFrame&>(frame).frameKind()) {
  case FrameKind::RequestHeader: {
    auto& reqHeader = dynamic_cast<const SSHRequestHeaderFrame&>(frame);
    downstream_state_ = reqHeader.authState();
    if (downstream_state_->channel_mode == ChannelMode::Handoff) {
      channel_id_remap_enabled_ = true;
      installMiddleware(this);
    }
    return version_exchanger_->writeVersion(downstream_state_->server_version);
  }
  case FrameKind::RequestCommon: {
    const auto& msg = dynamic_cast<const SSHRequestCommonFrame&>(frame).message();
    if (channel_id_remap_enabled_ && msg.isChannelMessage()) {
      auto& channelMsg = const_cast<wire::ChannelMsg&>(dynamic_cast<const wire::ChannelMsg&>(msg));
      channelMsg.getRecipientChannel() = channel_id_mappings_.at(channelMsg.getRecipientChannel());
    }
    return sendMessageToConnection(msg);
  }
  default:
    throw EnvoyException("bug: unknown frame kind");
  }
  (void)ctx;
  return absl::OkStatus();
}

absl::Status SshClientCodec::handleMessage(wire::SshMsg&& msg) {
  switch (msg.msg_type()) {
  case wire::SshMessageType::ServiceAccept: {
    const auto& acceptMsg = dynamic_cast<wire::ServiceAcceptMsg&>(msg);
    if (services_.contains(acceptMsg.service_name)) {
      return services_[acceptMsg.service_name]->handleMessage(std::move(msg));
    }
    ENVOY_LOG(error, "received ServiceAccept message for unknown service {}", msg.msg_type());
    return absl::InternalError(
        fmt::format("received ServiceAccept message for unknown service {}", msg.msg_type()));
  }
  case wire::SshMessageType::GlobalRequest: {
    const auto& globalReq = dynamic_cast<wire::GlobalRequestMsg&>(msg);
    if (globalReq.request_name == "hostkeys-00@openssh.com") {
      ENVOY_LOG(debug, "received hostkeys-00@openssh.com");
      // ignore this for now
      return absl::OkStatus();
    }
    ENVOY_LOG(debug, "forwarding global request");
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::ServiceAcceptMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::RequestSuccess: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::GlobalRequestSuccessMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::RequestFailure: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::GlobalRequestFailureMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Ignore: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::IgnoreMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Debug: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::DebugMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Unimplemented: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::UnimplementedMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Disconnect: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<wire::DisconnectMsg&&>(msg)));
    return absl::OkStatus();
  }
  default:
    PANIC("unimplemented");
  }
}

void SshClientCodec::writeToConnection(Envoy::Buffer::Instance& buf) const {
  return callbacks_->writeToConnection(buf);
}

absl::StatusOr<bytes> SshClientCodec::signWithHostKey(bytes_view<> in) const {
  auto hostKey = kex_result_->algorithms.host_key;
  if (auto k = kex_->getHostKey(hostKey); k) {
    return k->priv.sign(in);
  }
  return absl::InternalError("no such host key");
}

const AuthState& SshClientCodec::authState() const {
  return *downstream_state_;
};

AuthState& SshClientCodec::authState() {
  return *downstream_state_;
}

void SshClientCodec::forward(std::unique_ptr<SSHStreamFrame> frame) {
  switch (frame->frameKind()) {
  case FrameKind::ResponseHeader: {
    auto framePtr =
        std::unique_ptr<ResponseHeaderFrame>(dynamic_cast<SSHResponseHeaderFrame*>(frame.release()));
    callbacks_->onDecodingSuccess(std::move(framePtr));
    break;
  }
  case FrameKind::ResponseCommon: {
    auto framePtr =
        std::unique_ptr<ResponseCommonFrame>(dynamic_cast<ResponseCommonFrame*>(frame.release()));
    callbacks_->onDecodingSuccess(std::move(framePtr));
    // auto framePtr = dynamic_cast<SSHResponseCommonFrame*>(frame.release());
    // if (authState().channel_mode == ChannelMode::Handoff && !sent_response_header_frame_) {
    //   // we haven't yet sent a response header frame after handoff, transform the first one
    //   // into a header frame
    //   callbacks_->onDecodingSuccess(
    //       std::unique_ptr<ResponseHeaderFrame>(new SSHResponseHeaderFrame(framePtr, StreamStatus(0, true))));
    //   sent_response_header_frame_ = true;
    //   return;
    // }
    // callbacks_->onDecodingSuccess(std::unique_ptr<ResponseCommonFrame>(framePtr));
    break;
  }
  default:
    PANIC("bug: wrong frame type passed to SshClientCodec::forward");
  }
}

bool SshClientCodec::interceptMessage(wire::SshMsg& ssh_msg) {
  switch (ssh_msg.msg_type()) {
  case wire::SshMessageType::ChannelOpenConfirmation: {
    auto& confirm = dynamic_cast<wire::ChannelOpenConfirmationMsg&>(ssh_msg);
    const auto& info = downstream_state_->handoff_info;
    if (info.handoff_in_progress && confirm.recipient_channel == info.channel_info->downstream_channel_id()) {
      channel_id_mappings_[info.channel_info->internal_upstream_channel_id()] = confirm.sender_channel;
      // channel is open, now request a pty
      wire::ChannelRequestMsg channelReq;
      channelReq.recipient_channel = confirm.sender_channel;
      channelReq.want_reply = true;

      wire::PtyReqChannelRequestMsg ptyReq;
      ptyReq.term_env = info.pty_info->term_env();
      ptyReq.width_columns = info.pty_info->width_columns();
      ptyReq.height_rows = info.pty_info->height_rows();
      ptyReq.width_px = info.pty_info->width_px();
      ptyReq.height_px = info.pty_info->height_px();
      ptyReq.modes = info.pty_info->modes();

      channelReq.msg = ptyReq;
      auto _ = sendMessageToConnection(channelReq); // todo: handle error
      return false;
    }
    return true;
  }
  case wire::SshMessageType::ChannelOpenFailure: {
    const auto& failure = dynamic_cast<const wire::ChannelOpenFailureMsg&>(ssh_msg);
    if (failure.recipient_channel == downstream_state_->handoff_info.channel_info->downstream_channel_id()) {

      // couldn't connect to the upstream, bail out
      // still can't forward the message, the downstream thinks
      // the channel is already open
      callbacks_->onDecodingFailure(*failure.description);
      return false;
    }
    return true;
  }
  case wire::SshMessageType::UserAuthSuccess: {
    // upstream authenticated successfully; open a channel
    wire::ChannelOpenMsg openMsg;
    openMsg.channel_type = downstream_state_->handoff_info.channel_info->channel_type();
    openMsg.sender_channel = downstream_state_->handoff_info.channel_info->downstream_channel_id();
    openMsg.initial_window_size = downstream_state_->handoff_info.channel_info->initial_window_size();
    openMsg.max_packet_size = downstream_state_->handoff_info.channel_info->max_packet_size();
    auto _ = sendMessageToConnection(openMsg); // todo: handle status
    return false;
  }
  case wire::SshMessageType::UserAuthFailure: {
    const auto& failure = dynamic_cast<const wire::UserAuthFailureMsg&>(ssh_msg);
    callbacks_->onDecodingFailure(fmt::format("auth failure: {}", failure.methods));
    return false;
  }
  case wire::SshMessageType::ChannelSuccess: {
    if (downstream_state_->handoff_info.handoff_in_progress) {
      // open a shell
      // TODO: don't "hard code" this logic
      wire::ChannelRequestMsg shellReq;
      shellReq.recipient_channel = channel_id_mappings_[downstream_state_->handoff_info.channel_info->internal_upstream_channel_id()];
      shellReq.request_type = "shell";
      shellReq.want_reply = false;
      auto _ = sendMessageToConnection(shellReq);

      // handoff is complete, send an empty message to signal the downstream codec
      auto frame = std::make_unique<SSHResponseHeaderFrame>(authState().stream_id, StreamStatus(0, true), wire::IgnoreMsg{});
      frame->setRawFlags(0);
      callbacks_->onDecodingSuccess(std::move(frame));
      return false;
    }
    break;
  }
  case wire::SshMessageType::ChannelFailure: {
    if (downstream_state_->handoff_info.handoff_in_progress) {
      callbacks_->onDecodingFailure("failed to open upstream tty");
      return false;
    }
    break;
  }
  case wire::SshMessageType::Ignore:
  case wire::SshMessageType::Debug:
  case wire::SshMessageType::Unimplemented:
    if (downstream_state_->handoff_info.handoff_in_progress) {
      // ignore these messages during handoff, they can trigger a common frame to be sent too early
      return false;
    }
    break;
  default:
    break;
  }
  // doChannelIdRemap(sshMsg, channel_id_mappings_inverse_);
  return true;
}

void SshClientCodec::onInitialKexDone() {
  if (auto stat = user_auth_svc_->requestService(); !stat.ok()) {
    ENVOY_LOG(error, "error requesting user auth: {}", stat.message());
    callbacks_->onDecodingFailure(fmt::format("error requesting user auth: {}", stat.message()));
    return;
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec