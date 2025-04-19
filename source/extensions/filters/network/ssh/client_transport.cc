#include "source/extensions/filters/network/ssh/client_transport.h"

#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/transport.h"

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshClientTransport::SshClientTransport(
  Api::Api& api,
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr)
    : TransportBase(api, std::move(config)),
      tls_(slot_ptr) {
  wire::ExtInfoMsg extInfo;
  wire::PingExtension pingExt;
  pingExt.version = "0";
  extInfo.extensions->emplace_back(std::move(pingExt));
  outgoing_ext_info_ = std::move(extInfo);
}

void SshClientTransport::setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) {
  TransportBase::setCodecCallbacks(callbacks);
  initServices();
}

void SshClientTransport::initServices() {
  user_auth_svc_ = std::make_unique<UpstreamUserAuthService>(*this, api_);
  user_auth_svc_->registerMessageHandlers(*this);
  connection_svc_ = std::make_unique<UpstreamConnectionService>(*this, api_, tls_);
  connection_svc_->registerMessageHandlers(*this);
  ping_handler_ = std::make_unique<UpstreamPingExtensionHandler>(*this);
  ping_handler_->registerMessageHandlers(*this);

  services_[user_auth_svc_->name()] = user_auth_svc_.get();
  services_[connection_svc_->name()] = connection_svc_.get();
}

void SshClientTransport::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::ServiceAccept, this);
  dispatcher.registerHandler(wire::SshMessageType::GlobalRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::Ignore, this);
  dispatcher.registerHandler(wire::SshMessageType::Debug, this);
  dispatcher.registerHandler(wire::SshMessageType::Unimplemented, this);
  dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
}

void SshClientTransport::decode(Envoy::Buffer::Instance& buffer, bool end_stream) {
  if (upstream_is_direct_tcpip_) {
    wire::ChannelDataMsg data_msg;
    data_msg.recipient_channel = downstream_state_->handoff_info.channel_info->downstream_channel_id();
    data_msg.data = wire::flushTo<bytes>(buffer);
    forward(std::move(data_msg));
    return;
  }
  TransportBase::decode(buffer, end_stream);
}

GenericProxy::EncodingResult SshClientTransport::encode(const GenericProxy::StreamFrame& frame,
                                                        GenericProxy::EncodingContext&) {
  switch (frame.frameFlags().frameTags() & FrameTags::FrameTypeMask) {
  case FrameTags::RequestHeader: {
    auto& reqHeader = static_cast<const SSHRequestHeaderFrame&>(frame);
    downstream_state_ = reqHeader.authState();
    if (downstream_state_->channel_mode == ChannelMode::Handoff) {
      if (downstream_state_->allow_response->has_upstream()) {
        ASSERT(downstream_state_->handoff_info.handoff_in_progress);
        const auto& upstream = downstream_state_->allow_response->upstream();
        if (upstream.direct_tcpip()) {
          if (downstream_state_->multiplexing_info.multiplex_mode != MultiplexMode::None) {
            ENVOY_LOG(warn, "multiplexing not supported with direct-tcpip connections");
          }
          upstream_is_direct_tcpip_ = true;
          wire::ChannelOpenConfirmationMsg confirm;
          confirm.recipient_channel = downstream_state_->handoff_info.channel_info->downstream_channel_id();
          confirm.sender_channel = downstream_state_->handoff_info.channel_info->internal_upstream_channel_id();
          confirm.initial_window_size = downstream_state_->handoff_info.channel_info->initial_window_size();
          confirm.max_packet_size = downstream_state_->handoff_info.channel_info->max_packet_size();
          forwardHeader(std::move(confirm));
          return 0;
        }
      }
      channel_id_remap_enabled_ = true;
      installMiddleware(this);
    }
    if (downstream_state_->multiplexing_info.multiplex_mode == MultiplexMode::Source) {
      if (auto stat = connection_svc_->onStreamBegin(*downstream_state_, callbacks_->connection()->dispatcher()); !stat.ok()) {
        return stat;
      }
      callbacks_->connection()->addConnectionCallbacks(*this);
    }
    return version_exchanger_->writeVersion(downstream_state_->server_version);
  }
  case FrameTags::RequestCommon: {
    const auto& sshFrame = static_cast<const SSHRequestCommonFrame&>(frame);
    if (upstream_is_direct_tcpip_) {
      return sshFrame.message().visit(
        [this](const wire::ChannelDataMsg& msg) -> absl::StatusOr<size_t> {
          Envoy::Buffer::OwnedImpl buffer;
          // NB: ChannelDataMsg data is length-prefixed, but don't write the length here
          auto size = wire::write(buffer, *msg.data);
          callbacks_->writeToConnection(buffer);
          return size;
        },
        [](const auto& msg) -> absl::StatusOr<size_t> {
          return absl::InvalidArgumentError(fmt::format("unexpected message of type {} on direct-tcpip channel", msg.msg_type()));
        });
    }
    return sendMessageToConnection(sshFrame.message());
  }
  default:
    throw EnvoyException("bug: unknown frame kind");
  }
}

absl::StatusOr<size_t> SshClientTransport::sendMessageToConnection(const wire::Message& msg) {
  if (channel_id_remap_enabled_) {
    msg.visit(
      [&](wire::ChannelMsg auto& msg) {
        auto it = channel_id_mappings_.find(msg.recipient_channel);
        if (it != channel_id_mappings_.end()) {
          msg.recipient_channel = it->second;
        }
      },
      [](auto&) {});
  }
  return UpstreamTransportCallbacks::sendMessageToConnection(msg);
}

absl::Status SshClientTransport::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceAcceptMsg& msg) {
      if (services_.contains(msg.service_name)) {
        return services_[msg.service_name]->handleMessage(std::move(msg));
      }
      ENVOY_LOG(error, "received ServiceAccept message for unknown service {}", msg.msg_type());
      return absl::InternalError(
        fmt::format("received ServiceAccept message for unknown service {}", msg.msg_type()));
    },
    [&](wire::GlobalRequestMsg& msg) {
      if (msg.request_name() == "hostkeys-00@openssh.com") {
        ENVOY_LOG(debug, "received hostkeys-00@openssh.com");
        // ignore this for now
        return absl::OkStatus();
      }
      ENVOY_LOG(debug, "forwarding global request");
      forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](any_of<wire::GlobalRequestSuccessMsg,
               wire::GlobalRequestFailureMsg,
               wire::IgnoreMsg,
               wire::DebugMsg,
               wire::UnimplementedMsg,
               wire::DisconnectMsg> auto& msg) {
      forward(std::move(msg));
      return absl::OkStatus();
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

absl::StatusOr<bytes> SshClientTransport::signWithHostKey(bytes_view in) const {
  if (auto k = kex_->getHostKey(openssh::SSHKey::keyTypeFromName(kex_result_->algorithms.host_key)); k) {
    return k->priv.sign(in);
  }
  return absl::InternalError("no such host key");
}

const AuthState& SshClientTransport::authState() const {
  return *downstream_state_;
};

AuthState& SshClientTransport::authState() {
  return *downstream_state_;
}

void SshClientTransport::forward(wire::Message&& msg, FrameTags tags) {
  if (response_stream_header_sent_) [[likely]] {
    auto* framePtr = new SSHResponseCommonFrame(std::move(msg), tags);
    framePtr->setStreamId(streamId());
    callbacks_->onDecodingSuccess(std::unique_ptr<ResponseCommonFrame>(framePtr));
  } else {
    response_stream_header_sent_ = true;
    auto* framePtr = new SSHResponseHeaderFrame(std::move(msg), tags);
    framePtr->setStreamId(streamId());
    callbacks_->onDecodingSuccess(std::unique_ptr<ResponseHeaderFrame>(framePtr));
  }
}

void SshClientTransport::forwardHeader(wire::Message&& msg, FrameTags tags) {
  if (authState().upstream_ext_info.has_value() &&
      authState().upstream_ext_info->hasExtension<wire::PingExtension>()) {
    ping_handler_->enableForward(true);
  }
  forward(std::move(msg), FrameTags{tags | EffectiveHeader});
}

absl::StatusOr<bool> SshClientTransport::interceptMessage(wire::Message& ssh_msg) {
  return ssh_msg.visit(
    [&](wire::ChannelOpenConfirmationMsg& msg) -> absl::StatusOr<bool> {
      const auto& info = downstream_state_->handoff_info;
      if (info.handoff_in_progress && msg.recipient_channel == info.channel_info->downstream_channel_id()) {
        channel_id_mappings_[info.channel_info->internal_upstream_channel_id()] = msg.sender_channel;
        // channel is open, now request a pty
        wire::ChannelRequestMsg channelReq;
        channelReq.recipient_channel = msg.sender_channel;
        channelReq.want_reply = true;

        wire::PtyReqChannelRequestMsg ptyReq;
        ptyReq.term_env = info.pty_info->term_env();
        ptyReq.width_columns = info.pty_info->width_columns();
        ptyReq.height_rows = info.pty_info->height_rows();
        ptyReq.width_px = info.pty_info->width_px();
        ptyReq.height_px = info.pty_info->height_px();
        ptyReq.modes = info.pty_info->modes();

        channelReq.request = ptyReq;
        if (auto r = sendMessageToConnection(channelReq); !r.ok()) {
          return statusf("error requesting pty: {}", r.status());
        }
        return false;
      }
      return true;
    },
    [&](wire::ChannelOpenFailureMsg& msg) -> absl::StatusOr<bool> {
      if (msg.recipient_channel == downstream_state_->handoff_info.channel_info->downstream_channel_id()) {

        // couldn't connect to the upstream, bail out
        // still can't forward the message, the downstream thinks
        // the channel is already open
        onDecodingFailure(absl::UnavailableError(*msg.description));
        return false;
      }
      return true;
    },
    [&](wire::UserAuthSuccessMsg&) -> absl::StatusOr<bool> {
      wire::ChannelOpenMsg openMsg;
      openMsg.channel_type = downstream_state_->handoff_info.channel_info->channel_type();
      openMsg.sender_channel = downstream_state_->handoff_info.channel_info->downstream_channel_id();
      openMsg.initial_window_size = downstream_state_->handoff_info.channel_info->initial_window_size();
      openMsg.max_packet_size = downstream_state_->handoff_info.channel_info->max_packet_size();
      if (auto r = sendMessageToConnection(openMsg); !r.ok()) {
        return statusf("error opening channel: {}", r.status());
      }
      return false;
    },
    [&](wire::UserAuthFailureMsg&) -> absl::StatusOr<bool> {
      return absl::PermissionDeniedError("");
    },
    [&](wire::ChannelSuccessMsg&) -> absl::StatusOr<bool> {
      if (downstream_state_->handoff_info.handoff_in_progress) {
        // open a shell
        // TODO: don't "hard code" this logic
        wire::ChannelRequestMsg shellReq;
        shellReq.recipient_channel = channel_id_mappings_[downstream_state_->handoff_info.channel_info->internal_upstream_channel_id()];
        shellReq.request = wire::ShellChannelRequestMsg{};
        shellReq.want_reply = false;
        if (auto r = sendMessageToConnection(shellReq); !r.ok()) {
          return statusf("error requesting shell: {}", r.status());
        }

        // handoff is complete, send an empty message to signal the downstream codec
        forwardHeader(wire::IgnoreMsg{}, Sentinel);
        return false;
      }
      return true;
    },
    [&](wire::ChannelFailureMsg&) -> absl::StatusOr<bool> {
      if (downstream_state_->handoff_info.handoff_in_progress) {
        return absl::InternalError("failed to open upstream tty");
      }
      return true;
    },
    [&](any_of<wire::IgnoreMsg, wire::DebugMsg, wire::UnimplementedMsg> auto&) -> absl::StatusOr<bool> {
      if (downstream_state_->handoff_info.handoff_in_progress) {
        // ignore these messages during handoff, they can trigger a common frame to be sent too early
        return false;
      }
      return true;
    },
    [](auto&) -> absl::StatusOr<bool> { return true; });
}

void SshClientTransport::onInitialKexDone() {
  // send ext_info if we have it and the server supports it
  if (kex_result_->server_supports_ext_info) {
    auto extInfo = outgoingExtInfo();
    if (extInfo.has_value()) {
      if (auto r = sendMessageToConnection(*extInfo); !r.ok()) {
        onDecodingFailure(statusf("error sending ExtInfo: {}", r.status()));
      }
    }
  }

  if (auto stat = user_auth_svc_->requestService(); !stat.ok()) {
    onDecodingFailure(statusf("error requesting user auth: {}", stat));
    return;
  }
}

void SshClientTransport::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    connection_svc_->onStreamEnd();
  }
}

stream_id_t SshClientTransport::streamId() const {
  return downstream_state_->stream_id;
}

void SshClientTransport::onDecodingFailure(absl::Status err) {
  if (err.ok()) {
    ENVOY_LOG(info, "ssh: stream {} closing", streamId(), err.message());
  } else {
    ENVOY_LOG(error, "ssh: stream {} closing with error: {}", streamId(), err.message());
  }

  int code{};
  switch (err.code()) {
  case absl::StatusCode::kPermissionDenied:   code = SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE; break;
  case absl::StatusCode::kInvalidArgument:    code = SSH2_DISCONNECT_PROTOCOL_ERROR; break;
  case absl::StatusCode::kFailedPrecondition: code = SSH2_DISCONNECT_PROTOCOL_ERROR; break;
  default:                                    code = SSH2_DISCONNECT_BY_APPLICATION; break;
  }

  wire::DisconnectMsg msg;
  msg.reason_code = code;
  msg.description = statusToString(err);
  forwardHeader(std::move(msg), Error);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec