#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// ConnectionService

ConnectionService::ConnectionService(
  TransportCallbacks& callbacks,
  Peer direction)
    : transport_(callbacks),
      local_peer_(direction) {}

void ConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  msg_dispatcher_ = dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpen, this);
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

absl::StatusOr<uint32_t> ConnectionService::startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id) {
  if (!channel_id.has_value()) {
    auto internalId = transport_.channelIdManager().allocateNewChannel(local_peer_);
    if (!internalId.ok()) {
      return internalId.status();
    }
    channel_id = *internalId;
  }
  auto callbacks = std::make_unique<ChannelCallbacksImpl>(*this, *channel_id, local_peer_);
  if (auto stat = channel->setChannelCallbacks(*callbacks); !stat.ok()) {
    return stat;
  }
  LinkedList::moveIntoList(std::move(callbacks), channel_callbacks_);

  ENVOY_LOG(debug, "starting new internal channel: {}", *channel_id);
  RELEASE_ASSERT(!channels_.contains(*channel_id), fmt::format("bug: channel with ID {} already exists", *channel_id));
  channels_[*channel_id] = std::move(channel);

  return *channel_id;
}

absl::Status ConnectionService::handleMessage(wire::Message&& ssh_msg) {
  return ssh_msg.visit(
    [&](wire::ChannelOpenMsg& msg) {
      ENVOY_LOG(debug, "starting new passthrough channel");
      auto passthrough = std::make_unique<PassthroughChannel>();
      auto id = startChannel(std::move(passthrough));
      if (!id.ok()) {
        return statusf("error starting passthrough channel: {}", id.status());
      }
      auto stat = transport_.channelIdManager().bindChannelID(*id, PeerLocalID{
                                                                     .channel_id = msg.sender_channel,
                                                                     .local_peer = local_peer_,
                                                                   });
      ASSERT(stat.ok());
      // replace the sender channel id with the internal channel id
      msg.sender_channel = *id;
      // forward the message
      ENVOY_LOG(debug, "forwarding ChannelOpen message for passthrough channel: {}", *msg.sender_channel);
      transport_.forward(std::move(ssh_msg));

      return absl::OkStatus();
    },
    [&](wire::ChannelOpenConfirmationMsg& msg) {
      ENVOY_LOG(debug, "received ChannelOpenConfirmation message for internal channel: {} ({} id={})",
                *msg.recipient_channel,
                local_peer_,
                *msg.sender_channel);
      auto stat = transport_.channelIdManager().bindChannelID(msg.recipient_channel,
                                                              PeerLocalID{
                                                                .channel_id = msg.sender_channel,
                                                                .local_peer = local_peer_,
                                                              });
      if (!stat.ok()) {
        return statusf("received invalid ChannelOpenConfirmation message: {}", stat);
      }

      // If there is no existing channel for this ID already present, and the channel is owned
      // by the opposite peer, a passthrough channel is initialized for this ID.
      // Note: even if the channel is owned by the opposite peer, a local channel for that ID
      // can still be started ahead of time and will be used instead of a passthrough channel.
      if (auto stat = maybeStartPassthroughChannel(msg.recipient_channel); !stat.ok()) {
        return stat;
      }

      ASSERT(channels_.contains(msg.recipient_channel));
      ENVOY_LOG(debug, "internal channel opened successfully: id={}", *msg.recipient_channel);
      // Before passing the message to be handled by the channel, set both IDs to the internal ID
      // so that if the channel forwards the message, the sender ID will be correctly rewritten
      // to the ID we just tracked above
      msg.sender_channel = msg.recipient_channel;
      if (auto stat = channels_[msg.sender_channel]->onChannelOpened(std::move(msg)); !stat.ok()) {
        return statusf("error opening channel: {}", stat);
      }

      return absl::OkStatus();
    },
    [&](wire::ChannelOpenFailureMsg& msg) {
      // the channel will be immediately deleted after this, but the PassthroughChannel contains
      // the logic to forward the message, and this keeps things contistent
      if (auto stat = maybeStartPassthroughChannel(msg.recipient_channel); !stat.ok()) {
        return statusf("received invalid ChannelOpenFailure message: {}", stat);
      }

      auto node = channels_.extract(msg.recipient_channel);
      ASSERT(!node.empty());

      ENVOY_LOG(debug, "failed to open internal channel: id={}, err={}",
                *msg.recipient_channel, *msg.description);
      // node goes out of scope after this call, destroying the channel
      return node.mapped()->onChannelOpenFailed(std::move(msg));
    },
    [&](wire::ChannelCloseMsg& msg) {
      // After a ChannelCloseMsg has been received and the channel has processed it, the
      // Channel object is destroyed. At the protocol level, a ChannelCloseMsg must be both sent
      // and received for a channel to be closed. The Channel object is responsible for tracking
      // whether or not it has already sent a ChannelCloseMsg, and if not, it must send one here
      // before it is destroyed.
      ENVOY_LOG(debug, "received channel close: {}", msg.recipient_channel);
      auto node = channels_.extract(msg.recipient_channel);
      if (node.empty()) {
        // protocol error; end the connection
        return absl::InvalidArgumentError(fmt::format("received message for unknown channel {}: {}", msg.recipient_channel, msg.msg_type()));
      }
      // allow node to go out of scope
      auto stat = node.mapped()->readMessage(std::move(ssh_msg));
      ENVOY_LOG(debug, "destroying channel {}", msg.recipient_channel);
      return stat;
    },
    [&](wire::ChannelMsg auto& msg) -> absl::Status {
      if (auto it = channels_.find(msg.recipient_channel); it != channels_.end()) {
        return it->second->readMessage(std::move(ssh_msg));
      }
      // protocol error; end the connection
      return absl::InvalidArgumentError(fmt::format("received message for unknown channel {}: {}", msg.recipient_channel, msg.msg_type()));
    },
    [](auto&) {
      return absl::InternalError("unknown message");
    });
}

absl::Status ConnectionService::maybeStartPassthroughChannel(uint32_t internal_id) {
  if (channels_.contains(internal_id)) {
    return absl::OkStatus();
  }
  auto owner = transport_.channelIdManager().owner(internal_id);
  if (!owner.has_value()) {
    return absl::InvalidArgumentError(fmt::format("unknown channel {}", internal_id));
  }
  if (owner.value() == local_peer_) {
    return absl::InvalidArgumentError(fmt::format("expected channel {} to exist or be owned by the {} transport",
                                                  internal_id, local_peer_ == Peer::Upstream ? Peer::Downstream : Peer::Upstream));
  }
  auto passthrough = std::make_unique<PassthroughChannel>();
  return startChannel(std::move(passthrough), internal_id).status();
}

// ConnectionService::ChannelCallbacksImpl

ConnectionService::ChannelCallbacksImpl::ChannelCallbacksImpl(ConnectionService& parent, uint32_t channel_id, Peer local_peer)
    : parent_(parent),
      channel_id_mgr_(parent_.transport_.channelIdManager()),
      channel_id_(channel_id),
      local_peer_(local_peer),
      scope_(parent.transport_.statsScope().createScope("channel")) {}

void ConnectionService::ChannelCallbacksImpl::sendMessageLocal(wire::Message&& msg) {
  msg.visit(
    [&](wire::ChannelCloseMsg& msg) {
      msg.recipient_channel = channel_id_;
      auto stat = channel_id_mgr_.processOutgoingChannelMsg(msg, local_peer_);
      // This should always succeed, since we just set the recipient_channel ourselves.
      THROW_IF_NOT_OK(stat);

      close_timer_ = parent_.transport_.connectionDispatcher()->createTimer([this] {
        // If the grace period elapses and we don't receive a channel close reply, terminate the
        // connection. Protects against misbehaving clients who might ignore channel close to
        // keep a connection alive longer than they are permitted to, e.g. if we send a channel
        // close as a way to gracefully signal that the host is being drained.
        parent_.transport_.terminate(absl::DeadlineExceededError("timed out waiting for channel close"));
      });
      close_timer_->enableTimer(CloseResponseGracePeriod);
    },
    [&](wire::ChannelMsg auto& msg) {
      msg.recipient_channel = channel_id_;
      auto stat = channel_id_mgr_.processOutgoingChannelMsg(msg, local_peer_);
      // This should always succeed, since we just set the recipient_channel ourselves.
      THROW_IF_NOT_OK(stat);
    },
    [](auto&) {});
  // Errors here should always terminate the connection - this would either be a protocol error
  // or connection lost, etc. If the local peer isn't reachable, we can't "gracefully" close
  // this channel via ChannelCloseMsg, so defer to the transport for error handling and cleanup.
  // The channel calling this function wouldn't be able to do much else about an error at this
  // level either (this is not necessarily the case for sendMessageRemote, though).
  ENVOY_LOG(debug, "sending message to local channel {}: {}", channel_id_, msg.msg_type());
  if (auto stat = parent_.transport_.sendMessageToConnection(std::move(msg)); !stat.ok()) {
    parent_.transport_.terminate(stat.status());
  }
}

absl::Status ConnectionService::ChannelCallbacksImpl::sendMessageRemote(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ChannelMsg auto& msg) {
      msg.recipient_channel = channel_id_;
      auto stat = channel_id_mgr_.processOutgoingChannelMsg(msg, local_peer_ == Peer::Downstream
                                                                   ? Peer::Upstream
                                                                   : Peer::Downstream);
      if (!stat.ok()) {
        return stat;
      }
      ENVOY_LOG(debug, "sending messsage to remote channel {}: {}", *msg.recipient_channel, msg.msg_type());
      parent_.transport_.forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](auto&) -> absl::Status {
      throw Envoy::EnvoyException("bug: invalid message passed to sendMessageRemote()");
    });
}

void ConnectionService::ChannelCallbacksImpl::cleanup() {
  if (close_timer_ != nullptr) {
    close_timer_->disableTimer();
  }
  ASSERT(parent_.transport_.connectionDispatcher()->isThreadSafe());
  ENVOY_LOG(debug, "channel {}: cleanup", channel_id_);
  ASSERT(inserted());
  channel_id_mgr_.releaseChannelID(channel_id_, local_peer_);
  removeFromList(parent_.channel_callbacks_);
}

// UpstreamConnectionService

absl::Status UpstreamConnectionService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(std::move(req)).status();
}

absl::Status UpstreamConnectionService::onServiceAccepted() {
  return absl::OkStatus();
}

// DownstreamConnectionService

class HijackedChannel : public Channel,
                        public ChannelStreamCallbacks,
                        public Logger::Loggable<Logger::Id::filter> {
public:
  HijackedChannel(HijackedChannelCallbacks& hijack_callbacks,
                  std::unique_ptr<ChannelStreamServiceClient> channel_client,
                  const pomerium::extensions::ssh::InternalTarget& config,
                  const wire::ChannelOpenMsg& channel_open)
      : hijack_callbacks_(hijack_callbacks),
        channel_client_(std::move(channel_client)),
        config_(config),
        channel_open_(channel_open) {}

  void onStreamClosed(absl::Status err) override {
    if (!handoff_started_) {
      hijack_callbacks_.hijackedChannelFailed(err);
    }
  }

  absl::Status setChannelCallbacks(ChannelCallbacks& callbacks) override {
    auto stat = Channel::setChannelCallbacks(callbacks);
    ASSERT(stat.ok()); // default implementation always succeeds

    // Note: we're still inside of ConnectionService::startChannel() here, so the downstream ID has
    // not been bound yet. This callback doesn't send anything to the downstream currently, but if
    // it ever needs to then the ID will need to be bound earlier.

    // Start the stream and send the downstream's saved ChannelOpen message. The stream expects
    // the first message to be ChannelOpen (after the metadata is sent). It will respond with a
    // success or failure message.
    envoy::config::core::v3::Metadata metadata;
    if (config_.has_set_metadata()) {
      // use any metadata present in the set_metadata field
      metadata = config_.set_metadata();
    }

    pomerium::extensions::ssh::FilterMetadata sshMetadata;
    auto& typedMetadata = *metadata.mutable_typed_filter_metadata();
    if (auto it = typedMetadata.find("com.pomerium.ssh"); it != typedMetadata.end()) {
      // if there is already FilterMetadata present in the expected key, use it
      auto ok = it->second.UnpackTo(&sshMetadata);
      RELEASE_ASSERT(ok, "bug: invalid metadata in InternalTarget");
    }
    // set the channel id (this shouldn't be present if set_metadata is used)
    // XXX: should we use a separate key for this?
    sshMetadata.set_channel_id(callbacks_->channelId());

    // send the combined metadata
    typedMetadata["com.pomerium.ssh"].PackFrom(sshMetadata);
    channel_client_->start(this, std::move(metadata));

    sendMessageToStream(std::move(channel_open_)); // clear channel_open_
    return absl::OkStatus();
  }

  absl::Status onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& msg) override {
    switch (msg->message_case()) {
    case pomerium::extensions::ssh::ChannelMessage::kRawBytes: {
      wire::Message anyMsg{};
      auto stat = with_buffer_view(msg->raw_bytes().value(), [&anyMsg](Envoy::Buffer::Instance& buffer) {
        return anyMsg.decode(buffer, buffer.length());
      });
      if (!stat.ok()) {
        return statusf("received invalid channel message: {}", stat.status());
      }
      if (!anyMsg.has_value()) {
        return absl::InvalidArgumentError(fmt::format("received unknown channel message: {}", anyMsg.msg_type()));
      }
      return anyMsg.visit(
        [&](wire::ChannelOpenMsg&) -> absl::Status {
          return absl::UnimplementedError("cannot open channels from a hijacked stream");
        },
        [&](wire::ChannelOpenConfirmationMsg& msg) {
          if (open_complete_) {
            return absl::InvalidArgumentError("unexpected ChannelOpenConfirmation message");
          }
          open_complete_ = true;
          // ConnectionService normally calls this, but it never will for a hijacked channel since
          // it only handles messages on the read path (outgoing).
          // Note that the downstream channel ID has already been bound, so we don't need to do it
          // here like the ConnectionService would normally do.
          ENVOY_LOG(debug, "hijacked channel opened successfully");
          return onChannelOpened(std::move(msg));
        },
        [&](wire::ChannelOpenFailureMsg& msg) {
          // When this happens normally on the read path, the channel is destroyed after
          // onChannelOpenFailed is called by the ConnectionService. Here, this should trigger a
          // connection error.
          ENVOY_LOG(debug, "hijacked channel open failed");
          auto stat = onChannelOpenFailed(std::move(msg));
          ASSERT(!stat.ok()); // sanity check
          return stat;
        },
        [&](auto&) {
          if (!open_complete_) [[unlikely]] {
            return absl::InternalError(
              fmt::format("expected ChannelOpenConfirmation or ChannelOpenFailure, got {}", anyMsg.msg_type()));
          }
          ENVOY_LOG(debug, "channel {}: sending message to downstream: {}", callbacks_->channelId(), anyMsg.msg_type());
          callbacks_->sendMessageLocal(std::move(anyMsg));
          return absl::OkStatus();
        });
    }
    case pomerium::extensions::ssh::ChannelMessage::kChannelControl: {
      pomerium::extensions::ssh::SSHChannelControlAction ctrl_action;
      if (!msg->channel_control().has_control_action()) {
        return absl::InternalError("received invalid channel message: missing control action");
      }
      if (!msg->channel_control().control_action().UnpackTo(&ctrl_action)) {
        return absl::InternalError("received invalid channel message: failed to unpack control action");
      }
      switch (ctrl_action.action_case()) {
      case pomerium::extensions::ssh::SSHChannelControlAction::kHandOff: {
        if (ctrl_action.hand_off().upstream_auth().upstream().direct_tcpip()) {
          if (open_complete_) {
            return absl::FailedPreconditionError("direct-tcpip handoff requested after channel open confirmation");
          }
          open_complete_ = true;
        }
        if (!open_complete_) {
          return absl::FailedPreconditionError("handoff requested before channel open confirmation");
        }

        handoff_started_ = true; // allow the client to be closed without ending the connection
        auto* handOffMsg = ctrl_action.mutable_hand_off();
        hijack_callbacks_.initHandoff(handOffMsg);
        // set handoff complete here; we expect that initHandoff calls readDisable on the
        // downstream connection, so there will be nothing received until it is re-enabled
        // when the handoff is actually completed by the upstream
        handoff_complete_ = true;
        return absl::OkStatus();
      }
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

  absl::Status
  readMessage(wire::Message&& msg) override {
    if (!open_complete_) [[unlikely]] {
      return absl::InvalidArgumentError(fmt::format(
        "unexpected message received before channel open confirmation: {}", msg.msg_type()));
    }
    if (handoff_complete_) {
      return callbacks_->sendMessageRemote(std::move(msg));
    }
    sendMessageToStream(std::move(msg));
    return absl::OkStatus();
  }

  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&& msg) override {
    callbacks_->sendMessageLocal(std::move(msg));
    return absl::OkStatus();
  }

  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&& msg) override {
    // return an error here to end the connection, instead of going through the grpc callbacks
    return absl::InvalidArgumentError(*msg.description);
  }

private:
  void sendMessageToStream(wire::Message&& msg) {
    ChannelMessage channelMsg;
    google::protobuf::BytesValue b;
    auto msgData = encodeTo<std::string>(msg);
    // It should not be possible to end up with a message here that we can't encode. All messages
    // that get here would have been previously decoded, and the only modified fields would be
    // sender/receiver channel IDs.
    ASSERT(msgData.ok());
    *b.mutable_value() = *msgData;
    *channelMsg.mutable_raw_bytes() = b;
    channel_client_->sendMessage(channelMsg);
  }

  bool handoff_started_{false};
  bool handoff_complete_{false};
  bool open_complete_{false};
  HijackedChannelCallbacks& hijack_callbacks_;
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
  pomerium::extensions::ssh::InternalTarget config_;
  wire::ChannelOpenMsg channel_open_;
};

class OpenHijackedChannelMiddleware : public SshMessageMiddleware {
public:
  OpenHijackedChannelMiddleware(
    DownstreamConnectionService& parent,
    HijackedChannelCallbacks& hijack_callbacks,
    const pomerium::extensions::ssh::InternalTarget& config,
    std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client)
      : parent_(parent),
        hijack_callbacks_(hijack_callbacks),
        config_(config),
        grpc_client_(std::move(grpc_client)) {}

  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;

private:
  DownstreamConnectionService& parent_;
  HijackedChannelCallbacks& hijack_callbacks_;
  pomerium::extensions::ssh::InternalTarget config_;
  std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client_;
};

absl::StatusOr<MiddlewareResult> OpenHijackedChannelMiddleware::interceptMessage(wire::Message& msg) {
  return msg.visit(
    [&](wire::ChannelOpenMsg& msg) -> absl::StatusOr<MiddlewareResult> {
      auto client = std::make_unique<ChannelStreamServiceClient>(grpc_client_);

      auto channel = std::make_unique<HijackedChannel>(hijack_callbacks_, std::move(client), config_, msg);

      auto internalId = parent_.startChannel(std::move(channel), std::nullopt);
      if (!internalId.ok()) {
        return statusf("error starting channel: {}", internalId.status());
      }

      // This normally happens when ConnectionService::handleMessage processes an outgoing
      // ChannelOpenMsg, but we are going to drop the message here, and have it be handled by
      // the grpc server instead (the ConnectionService would otherwise create a PassthroughChannel
      // and forward the message).
      auto stat = parent_.transport_.channelIdManager().bindChannelID(
        *internalId,
        PeerLocalID{
          .channel_id = msg.sender_channel,
          .local_peer = Peer::Downstream,
        });
      // this can't fail, we allocated the internal ID just now
      THROW_IF_NOT_OK(stat);

      return MiddlewareResult::Break;
    },
    [](auto&) -> absl::StatusOr<MiddlewareResult> {
      return MiddlewareResult::Continue;
    });
}

DownstreamConnectionService::DownstreamConnectionService(
  TransportCallbacks& callbacks,
  std::shared_ptr<StreamTracker> stream_tracker)
    : ConnectionService(callbacks, Peer::Downstream),
      transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)),
      stream_tracker_(std::move(stream_tracker)) {}

void DownstreamConnectionService::registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(ServerMessage::kGlobalRequestResponse, this);
}

absl::Status DownstreamConnectionService::handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) {
  switch (message->message_case()) {
  case ServerMessage::kGlobalRequestResponse: {
    const auto& resp = message->global_request_response();
    if (resp.success()) {
      switch (resp.response_case()) {
      case pomerium::extensions::ssh::GlobalRequestResponse::kTcpipForwardResponse:
        return transport_.sendMessageToConnection(
                           wire::GlobalRequestSuccessMsg{
                             .response = wire::TcpipForwardResponseMsg{
                               .server_port = resp.tcpip_forward_response().server_port(),
                             },
                           })
          .status();
      case pomerium::extensions::ssh::GlobalRequestResponse::RESPONSE_NOT_SET:
        [[fallthrough]];
      default:
        return transport_.sendMessageToConnection(wire::GlobalRequestSuccessMsg{}).status();
      }
    }

    // The global request message doesn't include a description string, but it might still be
    // helpful to show one to the user.
    if (const auto& desc = resp.debug_message(); !desc.empty()) {
      wire::DebugMsg dbg{
        .always_display = true,
        .message = desc,
      };
      transport_.sendMessageToConnection(std::move(dbg)).IgnoreError();
    }

    return transport_.sendMessageToConnection(wire::GlobalRequestFailureMsg{}).status();
  } break;
  default:
    return absl::InternalError("invalid server message");
  }
}

void DownstreamConnectionService::onStreamBegin(Network::Connection& connection) {
  ASSERT(connection.dispatcher().isThreadSafe());
  stats_timer_ = connection.dispatcher().createTimer([this] {
    onStatsTimerFired();
  });
  stream_handle_ = stream_tracker_->onStreamBegin(transport_.streamId(), connection, *this, *this);
  stats_timer_->enableTimer(std::chrono::seconds(5));
}

void DownstreamConnectionService::onStreamEnd() {
  stats_timer_->disableTimer();
  stream_handle_.reset();
}

void DownstreamConnectionService::enableChannelHijack(
  HijackedChannelCallbacks& hijack_callbacks,
  const pomerium::extensions::ssh::InternalTarget& config,
  std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client) {
  ASSERT(msg_dispatcher_.has_value());
  ASSERT(open_hijacked_channel_middleware_ == nullptr);
  auto mw = std::make_unique<OpenHijackedChannelMiddleware>(*this, hijack_callbacks, config, grpc_client);
  msg_dispatcher_->installMiddleware(mw.get());
  open_hijacked_channel_middleware_ = std::move(mw);
}

void DownstreamConnectionService::disableChannelHijack() {
  // TODO: fix this up when refactoring the MessageDispatcher
  msg_dispatcher_->uninstallMiddleware(
    static_cast<OpenHijackedChannelMiddleware*>(open_hijacked_channel_middleware_.get()));
  open_hijacked_channel_middleware_.reset();
}

void DownstreamConnectionService::sendChannelEvent(const pomerium::extensions::ssh::ChannelEvent& ev) {
  switch (ev.event_case()) {
  case pomerium::extensions::ssh::ChannelEvent::kInternalChannelOpened:
    ENVOY_LOG(debug, "sending channel event: internal_channel_opened {{channel_id: {}, peer_address: {}}}",
              ev.internal_channel_opened().channel_id(),
              ev.internal_channel_opened().peer_address());
    break;
  case pomerium::extensions::ssh::ChannelEvent::kInternalChannelClosed:
    ENVOY_LOG(debug, "sending channel event: internal_channel_closed {{channel_id: {}, reason: {}}}",
              ev.internal_channel_closed().channel_id(),
              ev.internal_channel_closed().reason());
    break;
  case pomerium::extensions::ssh::ChannelEvent::kChannelStats:
    ENVOY_LOG(debug, "sending channel event: channel_stats");
    break;
  case pomerium::extensions::ssh::ChannelEvent::EVENT_NOT_SET:
    throw Envoy::EnvoyException("invalid channel event");
  }
  pomerium::extensions::ssh::StreamEvent stream_ev;
  *stream_ev.mutable_channel_event() = ev;
  ClientMessage msg;
  *msg.mutable_event() = stream_ev;
  transport_.sendMgmtClientMessage(msg);
}

void DownstreamConnectionService::onStatsTimerFired() {
  pomerium::extensions::ssh::ChannelEvent ev;
  auto* stats = ev.mutable_channel_stats();
  auto* items = stats->mutable_stats_list()->mutable_items();
  for (auto& ccb : channel_callbacks_) {
    auto sc = ccb->statsProvider();
    if (sc.has_value()) {
      auto* entry = items->Add();
      entry->set_channel_id(ccb->channelId());
      sc->populateChannelStats(*entry);
    }
  }
  sendChannelEvent(std::move(ev));
  stats_timer_->enableTimer(std::chrono::seconds(5));
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec