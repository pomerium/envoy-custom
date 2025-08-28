#include "source/extensions/filters/network/ssh/client_transport.h"

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/transport.h"

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshClientTransport::SshClientTransport(
  Envoy::Server::Configuration::ServerFactoryContext& context,
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
    : TransportBase(context.api(), std::move(config)) {
  wire::ExtInfoMsg extInfo;
  extInfo.extensions->emplace_back(wire::PingExtension{.version = "0"s});
  outgoing_ext_info_ = std::move(extInfo);
}

void SshClientTransport::setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) {
  TransportBase::setCodecCallbacks(callbacks);
  if (auto keys = openssh::loadHostKeys(codecConfig().host_keys()); !keys.ok()) {
    throw Envoy::EnvoyException(statusToString(keys.status()));
  } else {
    kex_->setHostKeys(std::move(*keys));
  }
  initServices();
}

void SshClientTransport::initServices() {
  user_auth_svc_ = std::make_unique<UpstreamUserAuthService>(*this, api_);
  connection_svc_ = std::make_unique<UpstreamConnectionService>(*this, api_);
  ping_handler_ = std::make_unique<PingExtensionHandler>(*this);

  services_[user_auth_svc_->name()] = user_auth_svc_.get();
  services_[connection_svc_->name()] = connection_svc_.get();
}

void SshClientTransport::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  // initial key exchange must be complete before handling any non-kex messages
  ASSERT(kex_result_ != nullptr);

  dispatcher.registerHandler(wire::SshMessageType::ServiceAccept, this);
  dispatcher.registerHandler(wire::SshMessageType::GlobalRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::Ignore, this);
  dispatcher.registerHandler(wire::SshMessageType::Debug, this);
  dispatcher.registerHandler(wire::SshMessageType::Unimplemented, this);
  dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);

  user_auth_svc_->registerMessageHandlers(*this);
  connection_svc_->registerMessageHandlers(*this);
  ping_handler_->registerMessageHandlers(*this);
}

void SshClientTransport::decode(Envoy::Buffer::Instance& buffer, bool end_stream) {
  if (upstream_is_direct_tcpip_) {
    wire::ChannelDataMsg data_msg;
    data_msg.recipient_channel = auth_state_->handoff_info.channel_info->downstream_channel_id();
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
    const auto& reqHeader = static_cast<const SSHRequestHeaderFrame&>(frame);
    auth_state_ = reqHeader.authState();
    if (auth_state_->channel_mode == ChannelMode::Handoff) {
      if (auth_state_->allow_response->has_upstream()) {
        ASSERT(auth_state_->handoff_info.handoff_in_progress);
        const auto& upstream = auth_state_->allow_response->upstream();
        if (upstream.direct_tcpip()) {
          upstream_is_direct_tcpip_ = true;
          wire::ChannelOpenConfirmationMsg confirm;
          confirm.recipient_channel = auth_state_->handoff_info.channel_info->downstream_channel_id();
          confirm.sender_channel = auth_state_->handoff_info.channel_info->internal_upstream_channel_id();
          confirm.initial_window_size = auth_state_->handoff_info.channel_info->initial_window_size();
          confirm.max_packet_size = auth_state_->handoff_info.channel_info->max_packet_size();
          if (auto stat = auth_state_->channel_id_mgr.processOutgoingChannelMsg(confirm, Peer::Downstream); !stat.ok()) {
            return stat;
          }
          forwardHeader(std::move(confirm));
          return 0;
        }
      }
      installMiddleware(&handoff_middleware_);
    }
    return version_exchanger_->writeVersion(auth_state_->server_version);
  }
  case FrameTags::RequestCommon: {
    if (!upstream_is_direct_tcpip_) {
      return sendMessageToConnection(extractFrameMessage(frame));
    }
    auto& sshFrame = static_cast<const SSHRequestCommonFrame&>(frame);
    return sshFrame.message().visit(
      [this](const wire::ChannelDataMsg& msg) -> absl::StatusOr<size_t> {
        Envoy::Buffer::OwnedImpl buffer;
        // Write msg.data directly to the upstream. The contents are treated as opaque.
        auto size = wire::write(buffer, *msg.data);
        callbacks_->writeToConnection(buffer);
        return size;
      },
      [](const wire::ChannelEOFMsg&) -> absl::StatusOr<size_t> {
        ENVOY_LOG(debug, "received ChannelEOF on direct-tcpip channel");
        // Downstream client on this channel is closed.
        // XXX: according to the RFC, this doesn't imply that we should end the entire connection,
        // but this seems fine for now given the expected usage of this feature.
        return absl::CancelledError("EOF");
      },
      [](const wire::ChannelCloseMsg&) -> absl::StatusOr<size_t> {
        ENVOY_LOG(debug, "received ChannelClose on direct-tcpip channel");
        return absl::CancelledError("channel closed");
      },
      [](const auto& msg) -> absl::StatusOr<size_t> {
        return absl::InvalidArgumentError(fmt::format("unexpected message of type {} on direct-tcpip channel", msg.msg_type()));
      });
  }
  default:
    throw EnvoyException("bug: unknown frame kind");
  }
}

absl::Status SshClientTransport::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceAcceptMsg& msg) {
      if (services_.contains(msg.service_name)) {
        return services_[msg.service_name]->onServiceAccepted();
      }
      ENVOY_LOG(error, "received ServiceAccept message for unknown service {}", msg.service_name);
      return absl::InvalidArgumentError(
        fmt::format("received ServiceAccept message for unknown service {}", msg.service_name));
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
               wire::DisconnectMsg> auto& msg) {
      forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::UnimplementedMsg& msg) {
      ENVOY_LOG(debug, "received UnimplementedMsg for sequence number {} (ignoring)", msg.sequence_number);
      return absl::OkStatus();
    },
    [](wire::IgnoreMsg&) {
      return absl::OkStatus();
    },
    [&](wire::DebugMsg& msg) {
      ENVOY_LOG(debug, "received DebugMsg: \"{}\"", msg.message);
      return absl::OkStatus();
    },
    [](auto& msg) {
      return absl::InternalError(fmt::format("received invalid message: {}", msg.msg_type()));
    });
}

AuthState& SshClientTransport::authState() {
  return *auth_state_;
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

void SshClientTransport::onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) {
  TransportBase::onKexCompleted(std::move(kex_result), initial_kex);

  if (!initial_kex) {
    return;
  }

  // send ext_info if we have it and the server supports it (only after the initial key exchange)
  if (kex_result_->server_supports_ext_info) {
    auto extInfo = outgoingExtInfo();
    if (extInfo.has_value()) {
      auto r = sendMessageToConnection(std::move(extInfo).value());
      RELEASE_ASSERT(r.ok(), fmt::format("failed to send ExtInfo: {}", r.status()));
    }
  }

  auto stat = user_auth_svc_->requestService();
  RELEASE_ASSERT(stat.ok(), fmt::format("failed to request service: {}", stat));
}

stream_id_t SshClientTransport::streamId() const {
  return auth_state_->stream_id;
}

void SshClientTransport::terminate(absl::Status err) {
  ENVOY_LOG(error, "ssh: stream {} closing with error: {}", streamId(), err.message());

  wire::DisconnectMsg msg;
  msg.reason_code = openssh::statusCodeToDisconnectCode(err.code());
  msg.description = statusToString(err);
  forwardHeader(std::move(msg), Error);
}

// Handoff Middleware

absl::StatusOr<MiddlewareResult> SshClientTransport::HandoffMiddleware::interceptMessage(wire::Message& ssh_msg) {
  const auto& info = self_.auth_state_->handoff_info;
  ASSERT(info.handoff_in_progress);

  return ssh_msg.visit(
    // 1: User auth request
    [&](wire::UserAuthSuccessMsg&) -> absl::StatusOr<MiddlewareResult> {
      auto channel = std::make_unique<HandoffChannel>(info, *this);
      auto stat = self_.connection_svc_->startChannel(std::move(channel), info.channel_info->internal_upstream_channel_id());
      if (!stat.ok()) {
        return stat.status();
      }

      // this message won't be dispatched to the upstream userauth service, so we need to handle a
      // couple of post-auth-success actions that it would normally do

      // set the upstream ext info if available
      if (auto info = self_.peerExtInfo(); info.has_value()) {
        self_.authState().upstream_ext_info = std::move(info);
      }
      // unregister the user auth service
      self_.unregisterHandler(self_.user_auth_svc_.get());

      return Break;
    },
    [&](wire::UserAuthFailureMsg&) -> absl::StatusOr<MiddlewareResult> {
      return absl::PermissionDeniedError("");
    },
    [&](any_of<wire::IgnoreMsg, wire::DebugMsg, wire::UnimplementedMsg> auto&) -> absl::StatusOr<MiddlewareResult> {
      // ignore these messages during handoff, they can trigger a common frame to be sent too early
      return Break;
    },
    [](auto& msg) -> absl::StatusOr<MiddlewareResult> {
      return absl::InternalError(fmt::format("received unexpected message from upstream during handoff: {}", msg.msg_type()));
    });
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec