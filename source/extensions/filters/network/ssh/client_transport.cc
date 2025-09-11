#include "source/extensions/filters/network/ssh/client_transport.h"

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
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

class HandoffMiddleware : public SshMessageMiddleware,
                          public Envoy::Event::DeferredDeletable {
public:
  explicit HandoffMiddleware(SshClientTransport& self) : parent_(self) {}
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;

  void cleanup() {
    parent_.connectionDispatcher()->deferredDelete(std::move(parent_.handoff_middleware_));
  }

private:
  SshClientTransport& parent_;
};

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
  connection_svc_ = std::make_unique<UpstreamConnectionService>(*this);
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
    data_msg.recipient_channel = auth_info_->handoff_info.channel_info->downstream_channel_id();
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
    auto& filterState = callbacks_->connection()->streamInfo().filterState();
    const auto& reqHeader = static_cast<const SSHRequestHeaderFrame&>(frame);
    // copy filter state objects shared by the downstream
    if (auto shared = reqHeader.downstreamSharedFilterStateObjects(); shared.has_value()) {
      for (auto obj : *shared) {
        filterState->setData(
          obj.name_, obj.data_, obj.state_type_, StreamInfo::FilterState::LifeSpan::Request);
      }
    }
    ASSERT(filterState->hasDataWithName(ChannelIDManagerFilterStateKey));
    ASSERT(filterState->hasDataWithName(AuthInfoFilterStateKey));

    auth_info_ = std::dynamic_pointer_cast<AuthInfo>(
      filterState->getDataSharedMutableGeneric(AuthInfoFilterStateKey));
    channel_id_manager_ = std::dynamic_pointer_cast<ChannelIDManager>(
      filterState->getDataSharedMutableGeneric(ChannelIDManagerFilterStateKey));
    if (auth_info_->channel_mode == ChannelMode::Handoff) {
      if (auth_info_->allow_response->has_upstream()) {
        ASSERT(auth_info_->handoff_info.handoff_in_progress);
        const auto& upstream = auth_info_->allow_response->upstream();
        // TODO: this is not ideal, should pull this logic out into a Channel implementation.
        if (upstream.direct_tcpip()) {
          auto internalId = auth_info_->handoff_info.channel_info->internal_upstream_channel_id();
          upstream_is_direct_tcpip_ = true;
          wire::ChannelOpenConfirmationMsg confirm;
          confirm.recipient_channel = auth_info_->handoff_info.channel_info->downstream_channel_id();
          confirm.sender_channel = internalId;
          confirm.initial_window_size = auth_info_->handoff_info.channel_info->initial_window_size();
          confirm.max_packet_size = auth_info_->handoff_info.channel_info->max_packet_size();
          // Logically, we are the upstream for this channel. The ID needs to be bound so that
          // the downstream can send messages to the "upstream" (us) on this channel correctly
          RETURN_IF_NOT_OK(channel_id_manager_->bindChannelID(internalId,
                                                              PeerLocalID{
                                                                .channel_id = internalId,
                                                                .local_peer = Peer::Upstream,
                                                              }));
          forwardHeader(std::move(confirm));
          return 0;
        }
      }
      auto mw = std::make_unique<HandoffMiddleware>(*this);
      installMiddleware(mw.get());
      handoff_middleware_ = std::move(mw); // TODO: move storage/cleanup logic into the message dispatcher
    }
    return version_exchanger_->writeVersion(auth_info_->server_version);
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

AuthInfo& SshClientTransport::authInfo() {
  return *auth_info_;
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
  if (authInfo().upstream_ext_info.has_value() &&
      authInfo().upstream_ext_info->hasExtension<wire::PingExtension>()) {
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
  return auth_info_->stream_id;
}

void SshClientTransport::terminate(absl::Status err) {
  ENVOY_LOG(error, "ssh: stream {} closing with error: {}", streamId(), err.message());

  wire::DisconnectMsg msg;
  msg.reason_code = openssh::statusCodeToDisconnectCode(err.code());
  msg.description = statusToString(err);
  forwardHeader(std::move(msg), Error);
}

// Handoff Middleware

class HandoffChannel : public Channel, public Logger::Loggable<Logger::Id::filter> {
public:
  HandoffChannel(const HandoffInfo& info, HandoffChannelCallbacks& callbacks)
      : info_(info),
        handoff_callbacks_(callbacks) {}

  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&&) override {
    if (info_.pty_info == nullptr) {
      return absl::InvalidArgumentError("session is not interactive");
    }

    ENVOY_LOG(debug, "handoff started");
    // 2: PTY open request
    wire::ChannelRequestMsg channelReq{
      .recipient_channel = callbacks_->channelId(),
      .want_reply = true,
      .request = wire::PtyReqChannelRequestMsg{
        .term_env = info_.pty_info->term_env(),
        .width_columns = info_.pty_info->width_columns(),
        .height_rows = info_.pty_info->height_rows(),
        .width_px = info_.pty_info->width_px(),
        .height_px = info_.pty_info->height_px(),
        .modes = info_.pty_info->modes(),
      },
    };
    auto stat = callbacks_->sendMessageToConnection(std::move(channelReq));
    if (!stat.ok()) {
      return statusf("error requesting pty: {}", stat);
    }
    return absl::OkStatus();
  }
  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&& msg) override {
    // this should end the connection
    return absl::UnavailableError(*msg.description);
  }

  absl::Status readMessage(wire::Message&& msg) override {
    if (handoff_complete_) {
      return callbacks_->passthrough(std::move(msg));
    }
    return msg.visit(
      // 3: Shell request
      [&](const wire::ChannelSuccessMsg&) {
        // open a shell; this logic is only reached after requesting a pty
        wire::ChannelRequestMsg shellReq;
        shellReq.recipient_channel = callbacks_->channelId();
        shellReq.request = wire::ShellChannelRequestMsg{};
        shellReq.want_reply = false;
        auto r = callbacks_->sendMessageToConnection(std::move(shellReq));
        RELEASE_ASSERT(r.ok(), "failed to send ShellChannelRequestMsg");

        ENVOY_LOG(debug, "handoff complete");
        handoff_complete_ = true;
        handoff_callbacks_.onHandoffComplete();

        return absl::OkStatus();
      },
      [&](const wire::ChannelFailureMsg&) {
        return absl::InternalError("failed to open upstream tty");
      },
      [](const auto& msg) {
        return absl::InternalError(fmt::format("invalid message received during handoff: {}", msg.msg_type()));
      });
  }

private:
  bool handoff_complete_{false};
  const HandoffInfo& info_;
  HandoffChannelCallbacks& handoff_callbacks_;
};

absl::StatusOr<MiddlewareResult> HandoffMiddleware::interceptMessage(wire::Message& ssh_msg) {
  const auto& info = parent_.auth_info_->handoff_info;
  ASSERT(info.handoff_in_progress);

  return ssh_msg.visit(
    // 1: User auth request
    [&](wire::UserAuthSuccessMsg&) -> absl::StatusOr<MiddlewareResult> {
      auto channel = std::make_unique<HandoffChannel>(info, parent_);
      auto internalId = parent_.connection_svc_->startChannel(
        std::move(channel), info.channel_info->internal_upstream_channel_id());
      ASSERT(internalId.ok()); // should not be able to fail

      if (auto stat = parent_.channel_id_manager_->bindChannelID(
            *internalId, PeerLocalID{
                           .channel_id = info.channel_info->downstream_channel_id(),
                           .local_peer = Peer::Downstream,
                         });
          !stat.ok()) {
        return statusf("error during handoff: {}", stat);
      }
      // Build and send the ChannelOpen message to the upstream
      wire::ChannelOpenMsg open;
      open.channel_type = "session";
      open.sender_channel = *internalId;
      open.initial_window_size = info.channel_info->initial_window_size();
      open.max_packet_size = info.channel_info->max_packet_size();

      auto stat = parent_.sendMessageToConnection(std::move(open));
      ASSERT(stat.ok()); // should not be able to fail

      // this message won't be dispatched to the upstream userauth service, so we need to handle a
      // couple of post-auth-success actions that it would normally do

      // set the upstream ext info if available
      if (auto info = parent_.peerExtInfo(); info.has_value()) {
        parent_.authInfo().upstream_ext_info = std::move(info);
      }
      // unregister the user auth service
      parent_.unregisterHandler(parent_.user_auth_svc_.get());

      cleanup();
      return Break | UninstallSelf;
    },
    [&](wire::UserAuthFailureMsg&) -> absl::StatusOr<MiddlewareResult> {
      return absl::PermissionDeniedError("");
    },
    [&](any_of<wire::IgnoreMsg, wire::DebugMsg, wire::UnimplementedMsg> auto&) -> absl::StatusOr<MiddlewareResult> {
      // ignore these messages during handoff, they can trigger a common frame to be sent too early
      return Break;
    },
    [](auto&) -> absl::StatusOr<MiddlewareResult> {
      return Continue;
    });
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec