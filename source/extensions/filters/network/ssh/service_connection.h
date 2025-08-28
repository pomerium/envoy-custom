#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/common/common/linked_object.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;

class ConnectionService : public virtual Service,
                          public virtual StreamCallbacks,
                          public Logger::Loggable<Logger::Id::filter> {
public:
  std::string name() override { return "ssh-connection"; };
  ConnectionService(TransportCallbacks& callbacks, Api::Api& api, Peer direction);
  ~ConnectionService() {
    while (!channel_callbacks_.empty()) {
      channel_callbacks_.front()->cleanup();
    }
  }

  // Note: channel lifetime
  // Creating channels and sending/receiving channel messages must only happen via ConnectionService
  // so that channel lifetimes can be managed properly. When a Channel object is passed to
  // startChannel, it will be opened by sending a ChannelOpen message, and waiting for a
  // ChannelOpenConfirmation reply (some channel types can override this logic however).
  // A Channel object is fully owned by the ConnectionService and should not be stored or referenced
  // elsewhere. It will be deleted automatically once the channel is considered "closed", which
  // occurs when both of the following conditions have been met:
  // 1. ChannelCallbacks::sendMessageToConnection has been called with a ChannelCloseMsg
  // 2. Channel::readMessage has been called with a ChannelCloseMsg
  // When a channel is considered closed, its internal ID is also released for re-use. This does
  // not occur until the ChannelCallbacks object is deleted (which may occur after the Channel).
  absl::StatusOr<uint32_t> startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id) final {
    if (!channel_id.has_value()) {
      auto internalId = transport_.authState().channel_id_mgr.newInternalChannel();
      if (!internalId.ok()) {
        return internalId.status();
      }
      channel_id = *internalId;
    }
    auto callbacks = std::make_unique<ChannelCallbacksImpl>(*this, *channel_id, local_peer_);
    channel->setChannelCallbacks(*callbacks);
    LinkedList::moveIntoList(std::move(callbacks), channel_callbacks_);

    auto& channelRef = *channel;
    pending_channels_[*channel_id] = std::move(channel);

    auto stat = channelRef.open();
    if (!stat.ok()) {
      return stat;
    }
    return *channel_id;
  }

  absl::Status handleMessage(wire::Message&& ssh_msg) override {
    auto& channelIdMgr = transport_.authState().channel_id_mgr;

    const auto visitChannelMsg = [&](wire::ChannelMsg auto& msg) -> absl::Status {
      // if the recipient channel is owned internally, handle the message ourselves
      if (auto it = open_channels_.find(msg.recipient_channel); it != open_channels_.end()) {
        return it->second->readMessage(ssh_msg);
      }

      // otherwise forward it to the opposite peer
      if (auto stat = channelIdMgr.processOutgoingChannelMsg(msg, local_peer_ == Peer::Downstream
                                                                    ? Peer::Upstream
                                                                    : Peer::Downstream);
          !stat.ok()) {
        return stat;
      }
      ENVOY_LOG(debug, "forwarding channel message: type={}, id={}", msg.msg_type(), *msg.recipient_channel);
      transport_.forward(std::move(msg));
      return absl::OkStatus();
    };

    return ssh_msg.visit(
      [&](wire::ChannelOpenMsg& msg) {
        if (auto stat = channelIdMgr.processIncomingChannelOpenMsg(msg, local_peer_); !stat.ok()) {
          return stat;
        }
        ENVOY_LOG(debug, "forwarding channel open request: id={}", *msg.sender_channel);
        transport_.forward(std::move(msg));
        return absl::OkStatus();
      },
      [&](wire::ChannelOpenConfirmationMsg& msg) {
        auto stat = channelIdMgr.processIncomingChannelOpenConfirmationMsg(msg, local_peer_);
        if (!stat.ok()) {
          return stat;
        }
        auto node = pending_channels_.extract(msg.recipient_channel);
        if (!node.empty()) {
          ENVOY_LOG(debug, "internal channel opened successfully: id={}", *msg.recipient_channel);
          if (auto stat = node.mapped()->onChannelOpened(); !stat.ok()) {
            return stat;
          }
          // promote the channel to open
          open_channels_.insert(std::move(node));
          // end here; the channel itself doesn't handle the ChannelOpenConfirmationMsg
          return absl::OkStatus();
        }
        return visitChannelMsg(msg);
      },
      [&](wire::ChannelOpenFailureMsg& msg) {
        // if the channel open fails, remove the channel from the pending list
        ENVOY_LOG(debug, "failed to open internal channel: id={}, err={}",
                  *msg.recipient_channel, *msg.description);
        auto node = pending_channels_.extract(msg.recipient_channel);
        if (!node.empty()) {
          return node.mapped()->onChannelOpenFailed(msg.description);
        }
        return visitChannelMsg(msg);
      },
      visitChannelMsg,
      [](auto&) {
        return absl::InternalError("unknown message");
      });
  }

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;

  class ChannelCallbacksImpl : public ChannelCallbacks,
                               public ::Envoy::Event::DeferredDeletable,
                               public LinkedObject<ChannelCallbacksImpl> {
  public:
    ChannelCallbacksImpl(ConnectionService& parent, uint32_t channel_id, Peer local_peer)
        : parent_(parent),
          channel_id_mgr_(parent_.transport_.authState().channel_id_mgr),
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

    uint32_t channelId() const override { return channel_id_; }

    void closeChannel(absl::Status err) override {
      if (closed_) {
        return;
      }
      closed_ = true;
      parent_.deleteChannel(channel_id_);
      cleanup();
      if (!err.ok()) {
        parent_.transport_.terminate(err);
      }
    }

    void cleanup() {
      ASSERT(inserted());
      ENVOY_LOG(debug, "releasing internal channel ID: {}", channel_id_);
      channel_id_mgr_.releaseInternalChannel(channel_id_);

      auto& dispatcher = *parent_.transport_.connectionDispatcher();
      ASSERT(dispatcher.isThreadSafe());
      dispatcher.deferredDelete(removeFromList(parent_.channel_callbacks_));
    }

  private:
    bool closed_{false};
    ConnectionService& parent_;
    ChannelIDManager& channel_id_mgr_;
    const uint32_t channel_id_;
    const Peer local_peer_;
  };

protected:
  void deleteChannel(uint32_t channel_id) {
    // auto& channelIdMgr = transport_.authState().channel_id_mgr;
    if (pending_channels_.contains(channel_id)) {
      // channelIdMgr.releaseInternalChannel(channel_id);
      pending_channels_.erase(channel_id);
      return;
    }

    ASSERT(open_channels_.contains(channel_id));
    // wire::ChannelCloseMsg close{
    //   .recipient_channel = channel_id,
    // };
    // auto stat = channelIdMgr.processOutgoingChannelMsg(close, local_peer_);
    // THROW_IF_NOT_OK(stat);
    // transport_.sendMessageToConnection(std::move(close)).IgnoreError();
    // channelIdMgr.releaseInternalChannel(channel_id);
    open_channels_.erase(channel_id);
  }

  TransportCallbacks& transport_;
  Api::Api& api_;
  const Peer local_peer_;

  std::unordered_map<uint32_t, std::unique_ptr<Channel>> open_channels_;
  std::unordered_map<uint32_t, std::unique_ptr<Channel>> pending_channels_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;
  std::list<std::unique_ptr<ChannelCallbacksImpl>> channel_callbacks_;
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