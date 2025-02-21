#include "source/extensions/filters/network/ssh/client_transport.h"

#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/transport.h"

extern "C" {
#include "openssh/ssherr.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshClientCodec::SshClientCodec(Api::Api& api,
                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                               AccessLog::AccessLogFileSharedPtr access_log)
    : TransportCallbacks(*this), api_(api), config_(std::move(config)), access_log_(access_log) {
  this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));
  user_auth_svc_ = std::make_unique<UpstreamUserAuthService>(*this, api);
  user_auth_svc_->registerMessageHandlers(*this);
  connection_svc_ = std::make_unique<UpstreamConnectionService>(*this, api, access_log);
  connection_svc_->registerMessageHandlers(*this);

  services_[user_auth_svc_->name()] = user_auth_svc_.get();
  services_[connection_svc_->name()] = connection_svc_.get();
}

void SshClientCodec::registerMessageHandlers(MessageDispatcher<SshMsg>& dispatcher) const {
  dispatcher.registerHandler(SshMessageType::ServiceAccept, this);
  dispatcher.registerHandler(SshMessageType::GlobalRequest, this);
  dispatcher.registerHandler(SshMessageType::RequestSuccess, this);
  dispatcher.registerHandler(SshMessageType::RequestFailure, this);
  dispatcher.registerHandler(SshMessageType::Ignore, this);
  dispatcher.registerHandler(SshMessageType::Debug, this);
  dispatcher.registerHandler(SshMessageType::Unimplemented, this);
  dispatcher.registerHandler(SshMessageType::Disconnect, this);
}

void SshClientCodec::setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) {
  callbacks_ = &callbacks;
  kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), false);
  kex_->registerMessageHandlers(*this);
  version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_);
  auto defaultState = new connection_state_t{};
  defaultState->cipher = NewUnencrypted();
  defaultState->direction_read = serverKeys;
  defaultState->direction_write = clientKeys;
  defaultState->seq_read = std::make_shared<uint32_t>(0);
  defaultState->seq_write = std::make_shared<uint32_t>(0);
  connection_state_.reset(defaultState);
}

void SshClientCodec::decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) {
  while (buffer.length() > 0) {
    if (!version_exchange_done_) {
      auto stat = version_exchanger_->readVersion(buffer);
      if (!stat.ok()) {
        ENVOY_LOG(error, "ssh: {}", stat.message());
        callbacks_->onDecodingFailure(stat.message());
        return;
      }
      version_exchange_done_ = true;
      continue;
    }

    Envoy::Buffer::OwnedImpl dec;
    auto stat = connection_state_->cipher->decryptPacket(*connection_state_->seq_read, dec, buffer);
    if (!stat.ok()) {
      ENVOY_LOG(error, "ssh: decryptPacket: {}", stat.message());
      callbacks_->onDecodingFailure(fmt::format("ssh: decryptPacket: {}", stat.message()));
      return;
    } else if (dec.length() == 0) {
      ENVOY_LOG(debug, "received incomplete packet; waiting for more data");
      return;
    }
    auto prev = (*connection_state_->seq_read)++;
    ENVOY_LOG(debug, "read seqnr inc: {} -> {}", prev, *connection_state_->seq_read);

    {
      auto anyMsg = readPacket<AnyMsg>(dec);
      if (!anyMsg.ok()) {
        ENVOY_LOG(error, "ssh: readPacket: {}", anyMsg.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: readPacket: {}", anyMsg.status().message()));
        return;
      }
      std::unique_ptr<SshMsg> msg = anyMsg->unwrap();
      if (msg->msg_type() == SshMessageType::NewKeys) {
        ENVOY_LOG(debug, "resetting read sequence number");
        *connection_state_->seq_read = 0;
      }
      ENVOY_LOG(info, "received message: type {}", msg->msg_type());
      if (auto err = dispatch(std::move(*msg)); !err.ok()) {
        ENVOY_LOG(error, "ssh: {}", err.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.message()));
        return;
      }
    }
  }
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
    if (channel_id_remap_enabled_ && msg.is_channel_message()) {
      auto& channelMsg = const_cast<ChannelMsg&>(dynamic_cast<const ChannelMsg&>(msg));
      channelMsg.get_recipient_channel() = channel_id_mappings_.at(channelMsg.get_recipient_channel());
    }
    return sendMessageToConnection(msg);
  }
  default:
    throw EnvoyException("bug: unknown frame kind");
  }
  (void)ctx;
  return absl::OkStatus();
}

void SshClientCodec::setKexResult(std::shared_ptr<kex_result_t> kex_result) {
  kex_result_ = kex_result;

  connection_state_->cipher = NewPacketCipher(
      connection_state_->direction_read,
      connection_state_->direction_write,
      kex_result.get());

  if (!first_kex_done_) {
    first_kex_done_ = true;

    if (auto stat = user_auth_svc_->requestService(); !stat.ok()) {
      ENVOY_LOG(error, "error requesting user auth: {}", stat.message());
      callbacks_->onDecodingFailure(fmt::format("error requesting user auth: {}", stat.message()));
      return;
    }
  }
}

absl::Status SshClientCodec::handleMessage(SshMsg&& msg) {
  switch (msg.msg_type()) {
  case SshMessageType::ServiceAccept: {
    const auto& acceptMsg = dynamic_cast<ServiceAcceptMsg&>(msg);
    if (services_.contains(acceptMsg.service_name)) {
      return services_[acceptMsg.service_name]->handleMessage(std::move(msg));
    }
    ENVOY_LOG(error, "received ServiceAccept message for unknown service {}", msg.msg_type());
    return absl::InternalError(
        fmt::format("received ServiceAccept message for unknown service {}", msg.msg_type()));
  }
  case SshMessageType::GlobalRequest: {
    const auto& globalReq = dynamic_cast<GlobalRequestMsg&>(msg);
    if (globalReq.request_name == "hostkeys-00@openssh.com") {
      ENVOY_LOG(debug, "received hostkeys-00@openssh.com");
      // ignore this for now
      return absl::OkStatus();
    }
    ENVOY_LOG(debug, "forwarding global request");
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<ServiceAcceptMsg&&>(msg)));
    return absl::OkStatus();
  }
  case SshMessageType::RequestSuccess: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<GlobalRequestSuccessMsg&&>(msg)));
    return absl::OkStatus();
  }
  case SshMessageType::RequestFailure: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<GlobalRequestFailureMsg&&>(msg)));
    return absl::OkStatus();
  }
  case SshMessageType::Ignore: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<IgnoreMsg&&>(msg)));
    return absl::OkStatus();
  }
  case SshMessageType::Debug: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<DebugMsg&&>(msg)));
    return absl::OkStatus();
  }
  case SshMessageType::Unimplemented: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<UnimplementedMsg&&>(msg)));
    return absl::OkStatus();
  }
  case SshMessageType::Disconnect: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     dynamic_cast<DisconnectMsg&&>(msg)));
    return absl::OkStatus();
  }
  default:
    PANIC("unimplemented");
  }
}

const connection_state_t& SshClientCodec::getConnectionState() const {
  return *connection_state_;
}

void SshClientCodec::writeToConnection(Envoy::Buffer::Instance& buf) const {
  return callbacks_->writeToConnection(buf);
}

const kex_result_t& SshClientCodec::getKexResult() const {
  return *kex_result_;
}

absl::StatusOr<bytes> SshClientCodec::signWithHostKey(bytes_view<> in) const {
  auto hostKey = kex_result_->Algorithms.host_key;
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

const pomerium::extensions::ssh::CodecConfig& SshClientCodec::codecConfig() const {
  return *config_;
};

bool SshClientCodec::interceptMessage(SshMsg& sshMsg) {
  switch (sshMsg.msg_type()) {
  case SshMessageType::ChannelOpenConfirmation: {
    auto& confirm = dynamic_cast<ChannelOpenConfirmationMsg&>(sshMsg);
    const auto& info = downstream_state_->handoff_info;
    if (info.handoff_in_progress && confirm.recipient_channel == info.channel_info->downstream_channel_id()) {
      channel_id_mappings_[info.channel_info->internal_upstream_channel_id()] = confirm.sender_channel;
      // channel is open, now request a pty
      ChannelRequestMsg channelReq;
      channelReq.recipient_channel = confirm.sender_channel;
      channelReq.want_reply = true;

      PtyReqChannelRequestMsg ptyReq;
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
  case SshMessageType::ChannelOpenFailure: {
    const auto& failure = dynamic_cast<const ChannelOpenFailureMsg&>(sshMsg);
    if (failure.recipient_channel == downstream_state_->handoff_info.channel_info->downstream_channel_id()) {

      // couldn't connect to the upstream, bail out
      // still can't forward the message, the downstream thinks
      // the channel is already open
      callbacks_->onDecodingFailure(*failure.description);
      return false;
    }
    return true;
  }
  case SshMessageType::UserAuthSuccess: {
    // upstream authenticated successfully; open a channel
    ChannelOpenMsg openMsg;
    openMsg.channel_type = downstream_state_->handoff_info.channel_info->channel_type();
    openMsg.sender_channel = downstream_state_->handoff_info.channel_info->downstream_channel_id();
    openMsg.initial_window_size = downstream_state_->handoff_info.channel_info->initial_window_size();
    openMsg.max_packet_size = downstream_state_->handoff_info.channel_info->max_packet_size();
    auto _ = sendMessageToConnection(openMsg); // todo: handle status
    return false;
  }
  case SshMessageType::UserAuthFailure: {
    const auto& failure = dynamic_cast<const UserAuthFailureMsg&>(sshMsg);
    callbacks_->onDecodingFailure(fmt::format("auth failure: {}", failure.methods));
    return false;
  }
  case SshMessageType::ChannelSuccess: {
    if (downstream_state_->handoff_info.handoff_in_progress) {
      // open a shell
      // TODO: don't "hard code" this logic
      ChannelRequestMsg shellReq;
      shellReq.recipient_channel = channel_id_mappings_[downstream_state_->handoff_info.channel_info->internal_upstream_channel_id()];
      shellReq.request_type = "shell";
      shellReq.want_reply = false;
      auto _ = sendMessageToConnection(shellReq);

      // handoff is complete, send an empty message to signal the downstream codec
      auto frame = std::make_unique<SSHResponseHeaderFrame>(authState().stream_id, StreamStatus(0, true), IgnoreMsg{});
      frame->setRawFlags(0);
      callbacks_->onDecodingSuccess(std::move(frame));
      return false;
    }
    break;
  }
  case SshMessageType::ChannelFailure: {
    if (downstream_state_->handoff_info.handoff_in_progress) {
      callbacks_->onDecodingFailure("failed to open upstream tty");
      return false;
    }
    break;
  }
  case SshMessageType::Ignore:
  case SshMessageType::Debug:
  case SshMessageType::Unimplemented:
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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec