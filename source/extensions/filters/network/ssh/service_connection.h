#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/common/common/linked_object.h"
#include "source/common/common/assert.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;

class ConnectionService : public virtual Service,
                          public virtual StreamCallbacks,
                          public Logger::Loggable<Logger::Id::filter> {
public:
  std::string name() override { return "ssh-connection"; };
  ConnectionService(TransportCallbacks& callbacks, Api::Api& api, Peer direction);

  // Channel Lifetime:
  // Creating channels and sending/receiving channel messages must only happen via ConnectionService
  // so that channel lifetimes can be managed properly. When a Channel object is passed to
  // startChannel, it will be opened by sending a ChannelOpen message, and waiting for a
  // ChannelOpenConfirmation reply (some channel types can override this logic however).
  // A Channel object is fully owned by the ConnectionService and should not be stored or referenced
  // elsewhere. It will be deleted automatically once the channel is considered "closed", which
  // occurs when a ChannelCloseMsg is received by the local peer, and has been processed by the
  // channel (i.e. it has been given the opportunity to respond with its own ChannelCloseMsg).
  // When a channel is considered closed, its internal ID is also released for re-use.
  absl::StatusOr<uint32_t> startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id = std::nullopt) final {
    if (!channel_id.has_value()) {
      auto internalId = transport_.authState().channel_id_mgr->allocateNewChannel(local_peer_);
      if (!internalId.ok()) {
        return internalId.status();
      }
      ENVOY_LOG(debug, "allocated new internal channel ID: {}", *internalId);
      channel_id = *internalId;
    }
    auto callbacks = std::make_unique<ChannelCallbacksImpl>(*this, *channel_id, local_peer_);
    channel->setChannelCallbacks(*callbacks);
    LinkedList::moveIntoList(std::move(callbacks), channel_callbacks_);

    ENVOY_LOG(debug, "new internal channel: {}", *channel_id);
    RELEASE_ASSERT(!channels_.contains(*channel_id), fmt::format("bug: channel with ID {} already exists", *channel_id));
    channels_[*channel_id] = std::move(channel);

    return *channel_id;
  }

  absl::Status handleMessage(wire::Message&& ssh_msg) override {
    auto& channelIdMgr = *transport_.authState().channel_id_mgr;

    return ssh_msg.visit(
      [&](wire::ChannelOpenMsg& msg) {
        ENVOY_LOG(debug, "starting new passthrough channel");
        auto passthrough = std::make_unique<PassthroughChannel>();
        auto id = startChannel(std::move(passthrough));
        if (!id.ok()) {
          return id.status();
        }
        auto stat = channelIdMgr.trackRelativeID(*id, RelativeChannelID{
                                                        .channel_id = msg.sender_channel,
                                                        .relative_to = local_peer_,
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
        auto stat = channelIdMgr.trackRelativeID(msg.recipient_channel,
                                                 RelativeChannelID{
                                                   .channel_id = msg.sender_channel,
                                                   .relative_to = local_peer_,
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

        ASSERT(channels_.contains(msg.sender_channel));
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
        auto owner = channelIdMgr.owner(msg.recipient_channel);
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
          return absl::InvalidArgumentError(fmt::format("received {} for unknown channel {}", msg.msg_type(), msg.recipient_channel));
        }
        // allow node to go out of scope
        return node.mapped()->readMessage(std::move(ssh_msg));
      },
      [&](wire::ChannelMsg auto& msg) -> absl::Status {
        if (auto it = channels_.find(msg.recipient_channel); it != channels_.end()) {
          return it->second->readMessage(std::move(ssh_msg));
        }
        // protocol error; end the connection
        return absl::InvalidArgumentError(fmt::format("received {} for unknown channel {}", msg.msg_type(), msg.recipient_channel));
      },
      [](auto&) {
        return absl::InternalError("unknown message");
      });
  }

  absl::Status maybeStartPassthroughChannel(uint32_t internal_id) {
    if (channels_.contains(internal_id)) {
      return absl::OkStatus();
    }
    auto owner = transport_.authState().channel_id_mgr->owner(internal_id);
    if (!owner.has_value()) {
      return absl::InvalidArgumentError(fmt::format("received ChannelOpenConfirmation for unknown channel {}", internal_id));
    }
    RELEASE_ASSERT(owner.value() != local_peer_, fmt::format("bug: expected channel {} to exist or be owned by the {} transport",
                                                             internal_id, local_peer_ == Peer::Upstream ? Peer::Downstream : Peer::Upstream));
    auto passthrough = std::make_unique<PassthroughChannel>();
    return startChannel(std::move(passthrough), internal_id).status();
  }

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;

  class ChannelCallbacksImpl final : public ChannelCallbacks,
                                     public LinkedObject<ChannelCallbacksImpl> {
  public:
    ChannelCallbacksImpl(ConnectionService& parent, uint32_t channel_id, Peer local_peer)
        : parent_(parent),
          channel_id_mgr_(*parent_.transport_.authState().channel_id_mgr),
          channel_id_(channel_id),
          local_peer_(local_peer) {}

    absl::Status sendMessageToConnection(wire::Message&& msg) override {
      // we do need to populate channel message IDs here
      auto stat = msg.visit(
        [&](wire::ChannelMsg auto& msg) {
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

    void passthrough(wire::Message&& msg) override {
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

    uint32_t channelId() const override {
      return channel_id_;
    }

    void cleanup() override {
      ASSERT(inserted());
      channel_id_mgr_.releaseChannel(channel_id_, local_peer_);
      removeFromList(parent_.channel_callbacks_);
    }

  private:
    ConnectionService& parent_;
    ChannelIDManager& channel_id_mgr_;
    const uint32_t channel_id_;
    const Peer local_peer_;
  };

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;
  const Peer local_peer_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;

  // field order is important: callbacks must not be destroyed before the channels are
  std::list<std::unique_ptr<ChannelCallbacksImpl>> channel_callbacks_;
  absl::flat_hash_map<uint32_t, std::unique_ptr<Channel>> channels_;
};

class DownstreamConnectionService final : public ConnectionService,
                                          public ChannelEventCallbacks {
public:
  DownstreamConnectionService(TransportCallbacks& callbacks,
                              Api::Api& api,
                              std::shared_ptr<StreamTracker> stream_tracker);

  void onStreamBegin(Network::Connection& connection);
  void onStreamEnd();
  void prepareOpenHijackedChannel(HijackedChannelCallbacks& hijack_callbacks,
                                  const pomerium::extensions::ssh::InternalTarget& config,
                                  std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client) {
    open_hijacked_channel_middleware_ =
      std::make_unique<OpenHijackedChannelMiddleware>(*this, hijack_callbacks, config, grpc_client);
    msg_dispatcher_->installMiddleware(open_hijacked_channel_middleware_.get());
  }

  void sendChannelEvent(const pomerium::extensions::ssh::ChannelEvent& ev) override {
    pomerium::extensions::ssh::StreamEvent stream_ev;
    *stream_ev.mutable_channel_event() = ev;
    ClientMessage msg;
    *msg.mutable_event() = stream_ev;
    transport_.sendMgmtClientMessage(msg);
  }

private:
  class OpenHijackedChannelMiddleware : public SshMessageMiddleware,
                                        public Envoy::Event::DeferredDeletable {
  public:
    OpenHijackedChannelMiddleware(DownstreamConnectionService& parent,
                                  HijackedChannelCallbacks& hijack_callbacks,
                                  const pomerium::extensions::ssh::InternalTarget& config,
                                  std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client)
        : parent_(parent),
          hijack_callbacks_(hijack_callbacks),
          config_(config),
          grpc_client_(grpc_client) {}

    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override {
      return msg.visit(
        [&](wire::ChannelOpenMsg& msg) -> absl::StatusOr<MiddlewareResult> {
          auto client = std::make_unique<ChannelStreamServiceClient>(grpc_client_);
          auto channel = std::make_unique<HijackedChannel>(hijack_callbacks_, std::move(client), config_, msg);

          auto channelId = parent_.startChannel(std::move(channel), std::nullopt);
          if (!channelId.ok()) {
            return channelId.status();
          }

          // synthesize a confirmation message to activate the channel internally
          wire::ChannelOpenConfirmationMsg confirm;
          confirm.sender_channel = msg.sender_channel;
          confirm.recipient_channel = *channelId;
          if (auto stat = parent_.handleMessage(std::move(confirm)); !stat.ok()) {
            return stat;
          }
          cleanup();
          return MiddlewareResult::Break | MiddlewareResult::UninstallSelf;
        },
        [](auto&) -> absl::StatusOr<MiddlewareResult> {
          return MiddlewareResult::Continue;
        });
    }

    void cleanup() {
      parent_.transport_.connectionDispatcher()->deferredDelete(
        std::move(parent_.open_hijacked_channel_middleware_));
    }

  private:
    DownstreamConnectionService& parent_;
    HijackedChannelCallbacks& hijack_callbacks_;
    pomerium::extensions::ssh::InternalTarget config_;
    std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client_;
  };
  DownstreamTransportCallbacks& transport_;

  std::shared_ptr<StreamTracker> stream_tracker_;
  std::unique_ptr<StreamHandle> stream_handle_;
  std::unique_ptr<OpenHijackedChannelMiddleware> open_hijacked_channel_middleware_;
};

class UpstreamConnectionService final : public ConnectionService,
                                        public UpstreamService {
public:
  UpstreamConnectionService(UpstreamTransportCallbacks& callbacks, Api::Api& api)
      : ConnectionService(callbacks, api, Peer::Upstream) {}
  absl::Status requestService() override;
  absl::Status onServiceAccepted() override;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec