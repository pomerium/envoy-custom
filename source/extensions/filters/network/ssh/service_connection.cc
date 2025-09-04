#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// ConnectionService

ConnectionService::ConnectionService(
  TransportCallbacks& callbacks,
  Api::Api& api,
  Peer direction)
    : transport_(callbacks),
      api_(api),
      local_peer_(direction) {
  (void)api_;
}

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
    return statusf("failed to start channel: {}", stat);
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
        return id.status();
      }
      auto stat = transport_.channelIdManager().bindChannelID(*id, PeerLocalID{
                                                                     .channel_id = msg.sender_channel,
                                                                     .local_peer = local_peer_,
                                                                   });
      THROW_IF_NOT_OK(stat);
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
        return stat;
      }

      return absl::OkStatus();
    },
    [&](wire::ChannelOpenFailureMsg& msg) {
      auto owner = transport_.channelIdManager().owner(msg.recipient_channel);
      if (!owner.has_value()) {
        return absl::InvalidArgumentError(fmt::format("received ChannelOpenFailureMsg message for unknown channel {}", msg.recipient_channel));
      }
      // the channel will be immediately deleted after this, but the PassthroughChannel contains
      // the logic to forward the message, and this keeps things contistent
      if (auto stat = maybeStartPassthroughChannel(msg.recipient_channel); !stat.ok()) {
        return stat;
      }

      auto node = channels_.extract(msg.recipient_channel);
      if (node.empty()) {
        return absl::InvalidArgumentError(fmt::format("received ChannelOpenFailureMsg message for unknown channel {}", msg.recipient_channel));
      }
      // if the channel open fails, remove the channel from the pending list
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

      auto node = channels_.extract(msg.recipient_channel);
      if (node.empty()) {
        // protocol error; end the connection
        return absl::InvalidArgumentError(fmt::format("received message for unknown channel {}: {}", msg.recipient_channel, msg.msg_type()));
      }
      // allow node to go out of scope
      return node.mapped()->readMessage(std::move(ssh_msg));
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
    return absl::InvalidArgumentError(fmt::format("received ChannelOpenConfirmation for unknown channel {}", internal_id));
  }
  RELEASE_ASSERT(owner.value() != local_peer_, fmt::format("bug: expected channel {} to exist or be owned by the {} transport",
                                                           internal_id, local_peer_ == Peer::Upstream ? Peer::Downstream : Peer::Upstream));
  auto passthrough = std::make_unique<PassthroughChannel>();
  return startChannel(std::move(passthrough), internal_id).status();
}

// ConnectionService::ChannelCallbacksImpl

ConnectionService::ChannelCallbacksImpl::ChannelCallbacksImpl(ConnectionService& parent, uint32_t channel_id, Peer local_peer)
    : parent_(parent),
      channel_id_mgr_(parent_.transport_.channelIdManager()),
      channel_id_(channel_id),
      local_peer_(local_peer) {}

absl::Status ConnectionService::ChannelCallbacksImpl::sendMessageToConnection(wire::Message&& msg) {
  auto stat = msg.visit(
    [&](wire::ChannelMsg auto& msg) {
      // TODO: should we populate channel IDs here or require the caller to fill them in?
      msg.recipient_channel = channel_id_;
      return channel_id_mgr_.processOutgoingChannelMsg(msg, local_peer_);
    },
    [](auto&) {
      return absl::OkStatus();
    });
  if (!stat.ok()) {
    return stat;
  }
  return parent_.transport_.sendMessageToConnection(std::move(msg))
    .status();
}

void ConnectionService::ChannelCallbacksImpl::passthrough(wire::Message&& msg) {
  msg.visit(
    [&](wire::ChannelMsg auto& msg) {
      auto stat = channel_id_mgr_.processOutgoingChannelMsg(msg, local_peer_ == Peer::Downstream
                                                                   ? Peer::Upstream
                                                                   : Peer::Downstream);
      THROW_IF_NOT_OK(stat);
      ENVOY_LOG(debug, "forwarding channel message: type={}, id={}", msg.msg_type(), *msg.recipient_channel);
      parent_.transport_.forward(std::move(msg));
    },
    [&](auto&) {
      throw Envoy::EnvoyException("bug: invalid message passed to passthrough()");
    });
}

void ConnectionService::ChannelCallbacksImpl::cleanup() {
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

  ~HijackedChannel() {
    if (stream_ != nullptr) {
      unsetCallbacksAndResetStream();
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
    stream_ = channel_client_->start(this, std::move(metadata));
    channel_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus code, std::string err) {
      // This callback is unregistered on handoff.
      hijack_callbacks_.hijackedChannelFailed(absl::Status(static_cast<absl::StatusCode>(code), err));
    });
    return sendMessageToStream(std::move(channel_open_)); // clear channel_open_
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
      return anyMsg.visit(
        [&](wire::ChannelOpenMsg&) -> absl::Status {
          throw Envoy::EnvoyException("cannot open channels from a hijacked stream");
        },
        [&](wire::ChannelOpenConfirmationMsg& msg) {
          if (open_complete_) {
            throw Envoy::EnvoyException("unexpected ChannelOpenConfirmationMsg");
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
          ENVOY_LOG(debug, "sending channel message to downstream: {}", anyMsg.msg_type());
          return callbacks_->sendMessageToConnection(std::move(anyMsg));
        });
    }
    case pomerium::extensions::ssh::ChannelMessage::kChannelControl: {
      pomerium::extensions::ssh::SSHChannelControlAction ctrl_action;
      msg->channel_control().control_action().UnpackTo(&ctrl_action);
      switch (ctrl_action.action_case()) {
      case pomerium::extensions::ssh::SSHChannelControlAction::kHandOff: {
        // allow the client to be closed without ending the connection
        unsetCallbacksAndResetStream();
        auto* handOffMsg = ctrl_action.mutable_hand_off();
        hijack_callbacks_.initHandoff(handOffMsg);
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

  absl::Status readMessage(wire::Message&& msg) override {
    if (handoff_complete_) {
      callbacks_->passthrough(std::move(msg));
      return absl::OkStatus();
    }
    return sendMessageToStream(std::move(msg));
  }

  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&& msg) override {
    return callbacks_->sendMessageToConnection(std::move(msg));
  }

  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&& msg) override {
    // return an error here to end the connection, instead of going through the grpc callbacks
    unsetCallbacksAndResetStream();
    return absl::InvalidArgumentError(*msg.description);
  }

private:
  absl::Status sendMessageToStream(wire::Message&& msg) {
    ChannelMessage channelMsg;
    google::protobuf::BytesValue b;
    auto msgData = encodeTo<std::string>(msg);
    if (!msgData.ok()) {
      return absl::InvalidArgumentError(fmt::format("received invalid message: {}", msgData.status()));
    }
    *b.mutable_value() = *msgData;
    *channelMsg.mutable_raw_bytes() = b;
    stream_->sendMessage(channelMsg, false);
    return absl::OkStatus();
  }

  void unsetCallbacksAndResetStream() {
    channel_client_->setOnRemoteCloseCallback(nullptr);
    stream_->resetStream();
    stream_ = nullptr;
  }

  bool handoff_complete_{false};
  bool open_complete_{false};
  HijackedChannelCallbacks& hijack_callbacks_;
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
  Grpc::AsyncStream<ChannelMessage> stream_;
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
        return internalId.status();
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
  Api::Api& api,
  std::shared_ptr<StreamTracker> stream_tracker)
    : ConnectionService(callbacks, api, Peer::Downstream),
      transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)),
      stream_tracker_(std::move(stream_tracker)) {}

void DownstreamConnectionService::onStreamBegin(Network::Connection& connection) {
  ASSERT(connection.dispatcher().isThreadSafe());

  stream_handle_ = stream_tracker_->onStreamBegin(transport_.streamId(), connection, *this, *this);
}

void DownstreamConnectionService::onStreamEnd() {
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
  pomerium::extensions::ssh::StreamEvent stream_ev;
  *stream_ev.mutable_channel_event() = ev;
  ClientMessage msg;
  *msg.mutable_event() = stream_ev;
  transport_.sendMgmtClientMessage(msg);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec