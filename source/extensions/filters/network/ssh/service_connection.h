#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/common/common/linked_object.h"
#include "source/common/common/callback_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;
constexpr auto CloseResponseGracePeriod = std::chrono::seconds(2);

class ConnectionService : public virtual Service,
                          public virtual StreamCallbacks,
                          public Logger::Loggable<Logger::Id::filter> {
public:
  std::string name() override { return "ssh-connection"; };
  ConnectionService(TransportCallbacks& callbacks, Peer direction);

  // Channel Lifetime:
  // Creating channels and sending/receiving channel messages must only happen via ConnectionService
  // so that channel lifetimes can be managed properly. A Channel object is fully owned by the
  // ConnectionService and should not be stored or referenced elsewhere after it is passed to
  // startChannel().
  //
  // Handling ChannelOpen and ChannelClose messages:
  // How/when the ChannelOpen is sent is left as an implementation detail specific to each Channel
  // type. ChannelOpen messages are not sent automatically by the ConnectionService (but may be
  // sent automatically as part of the implementation of a specific Channel).
  // Likewise, sending a ChannelClose message is the responsibility of each Channel implementation,
  // and is not handled automatically. However, *receiving* a ChannelClose message will trigger
  // the channel to be destroyed immediately after the call to Channel::readMessage() returns.
  // Therefore, it is crucial that all Channel implementations properly handle receiving a
  // ChannelClose message by replying with their own ChannelClose message on the channel if they
  // have not done so already (i.e. if the ChannelClose was received as an expected response to
  // one sent previously).
  absl::StatusOr<uint32_t> startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id = std::nullopt) final;
  void onServerDraining(std::chrono::milliseconds delay) final;

  absl::Status handleMessage(wire::Message&& ssh_msg) override;
  absl::Status maybeStartPassthroughChannel(uint32_t internal_id);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  void shutdown(absl::Status err);

  class ChannelCallbacksImpl final : public ChannelCallbacks,
                                     public LinkedObject<ChannelCallbacksImpl> {
  public:
    ChannelCallbacksImpl(ConnectionService& parent, uint32_t channel_id, Peer local_peer);
    void sendMessageLocal(wire::Message&& msg) override;
    absl::Status sendMessageRemote(wire::Message&& msg) override;
    uint32_t channelId() const override { return channel_id_; }
    Stats::Scope& scope() const override { return *scope_; }
    void setStatsProvider(ChannelStatsProvider& stats_provider) override { stats_provider_ = stats_provider; }
    Envoy::OptRef<ChannelStatsProvider> statsProvider() const { return stats_provider_; }
    void terminate(absl::Status err) override {
      parent_.transport_.terminate(err);
    }

    [[nodiscard]]
    Envoy::Common::CallbackHandlePtr addInterruptCallback(std::function<void(absl::Status, TransportCallbacks& transport)> cb) override;

    void runInterruptCallbacks(absl::Status err) override {
      interrupt_callbacks_->runCallbacks(err, parent_.transport_);
      // Reset the interrupt callback manager. This will deactivate all existing handles such that
      // deleting them becomes a no-op.
      interrupt_callbacks_ = std::make_unique<Envoy::Common::CallbackManager<void, absl::Status, TransportCallbacks&>>();
    }

  private:
    void cleanup() override;
    ConnectionService& parent_;
    ChannelIDManager& channel_id_mgr_;
    const uint32_t channel_id_;
    const Peer local_peer_;
    Stats::ScopeSharedPtr scope_;
    Envoy::Event::TimerPtr close_timer_;
    Envoy::OptRef<ChannelStatsProvider> stats_provider_;
    std::unique_ptr<Envoy::Common::CallbackManager<void, absl::Status, TransportCallbacks&>> interrupt_callbacks_;
  };

protected:
  // Initiates a channel close from Envoy, bypassing the normal channel close sequence. This will
  // propagate to both peers and close the channel as normal.
  //
  // Warning: Before calling this function, ensure ChannelIDManager::isPreemptable() returns true
  // given the channel ID and local peer.
  //
  //
  // When preempting a channel, the following sequence of events occurs:
  //  1. The channel is marked as preempted (see ChannelIDManager::preempt)
  //  2. If any interrupt callbacks have been added, they are invoked.
  //  3. Envoy sends a ChannelClose message to the local peer.
  //  4. The local peer replies with its own ChannelClose message.
  //  5. The local Channel receives the close message, and sends a ChannelClose message of its own
  //     to the remote peer (if one exists).
  //  6. The local Channel is destroyed, and invokes ChannelCallbacks::cleanup(), releasing the
  //     channel ID for the local peer.
  //  7. The remote peer receives the ChannelClose message (sent in step 5) and replies with a
  //     ChannelClose message of its own.
  //  8. The remote channel processes the ChannelClose message, and sends one to its peer
  //     (the local peer from our perspective).
  //     Note: at this point, the local channel thinks it has already received a ChannelClose
  //     from its remote peer, so the real local client will have actually closed that channel
  //     and we can't send anything to it.
  //  9. The remote peer transport requests the ChannelIDManager to process its outgoing
  //     ChannelClose message (sent in step 8), and the ChannelIDManager returns a flag indicating
  //     the message should be dropped. The message is dropped.
  // 10. The remote peer's Channel is destroyed, and its channel ID is released. Both sides are now
  //     released, so the internal channel is freed.
  //
  // Preempting a channel will send a ChannelClose message to the *local* peer, regardless
  // of which side created the channel. Therefore, the local peer's channel must be in a state
  // where it is able to accept a ChannelClose, otherwise this is a protocol error. Whether or not
  // we can know the channel is in such a state depends on which peer originally opened the channel:
  //
  // If the local peer sent the channel open request:
  //   This Channel instance would have received and forwarded a ChannelOpen message. If the
  //   remote peer replies with a ChannelOpenConfirmation message, this Channel instance would
  //   NOT have observed it. The channel is only open once the local peer receives the
  //   ChannelOpenConfirmation, but determining if this has occurred is not possible from this
  //   side.
  //
  // If the remote peer sent the channel open request:
  //   This Channel instance would NOT have observed the ChannelOpen message. If the local peer
  //   replies with a ChannelOpenConfirmation message, this Channel instance would have observed
  //   it and would be able to determine that the channel is open. However, there is still a
  //   possible race if the remote peer decides to send a ChannelClose request for another reason
  //   after the interrupt and before the local peer has a chance to reply with its own
  //   ChannelClose. If that happens, then the local peer would receive two ChannelClose messages
  //   for the same channel the second of which would be a protocol error.
  //
  // In general, therefore, it is not reliable for a single half of the transport to determine
  // whether it can initiate a channel close internally without causing a protocol error. Instead,
  // this state is tracked by the ChannelIDManager, which is shared between both sides of the
  // transport. When one side of the transport calls ChannelIDManager::preempt() on an eligible
  // ID (see ChannelIDManager::isPreemptable), it changes the channel's state to 'Preempted'.
  // Then, further calls to ChannelIDManager::processOutgoingChannelMsg can return a flag indicating
  // that the message about to be sent should instead be dropped.
  //
  // Note: In the shutdown() case, all local channels are closed at the same time. This usually
  // results in the local client sending a DisconnectMsg after the last channel is closed. When
  // that happens, the upstream is reset immediately and the sequence above skips over steps
  // 7-9, and step 10 happens when the filter chain is destroyed, while parent_.channel_callbacks_
  // is being deleted.
  void preempt(ChannelCallbacks& ccb, absl::Status err);

  TransportCallbacks& transport_;
  const Peer local_peer_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;

  // field order is important: callbacks must not be destroyed before the channels are
  std::list<std::unique_ptr<ChannelCallbacksImpl>> channel_callbacks_;
  absl::flat_hash_map<uint32_t, std::unique_ptr<Channel>> channels_;
  Envoy::Common::CallbackHandlePtr drain_callback_;
};

class HijackedChannelCallbacks {
public:
  virtual ~HijackedChannelCallbacks() = default;
  virtual void initHandoff(pomerium::extensions::ssh::SSHChannelControlAction_HandOffUpstream*) PURE;
  virtual pomerium::extensions::ssh::InternalCLIModeHint modeHint() const PURE;
};

class DownstreamConnectionService final : public ConnectionService,
                                          public StreamMgmtServerMessageHandler,
                                          public ChannelEventCallbacks {
  friend class OpenHijackedChannelMiddleware;

public:
  DownstreamConnectionService(TransportCallbacks& callbacks,
                              std::shared_ptr<StreamTracker> stream_tracker);

  void onStreamBegin(Network::Connection& connection);
  void onStreamEnd();
  void enableChannelHijack(HijackedChannelCallbacks& hijack_callbacks,
                           const pomerium::extensions::ssh::InternalTarget& config,
                           Envoy::Grpc::RawAsyncClientSharedPtr grpc_client);
  void disableChannelHijack();

  void sendChannelEvent(const pomerium::extensions::ssh::ChannelEvent& ev) override;

  using ConnectionService::handleMessage;
  using ConnectionService::registerMessageHandlers;

  void registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;

private:
  void onStatsTimerFired();

  DownstreamTransportCallbacks& transport_;

  std::shared_ptr<StreamTracker> stream_tracker_;
  std::unique_ptr<StreamHandle> stream_handle_;
  std::unique_ptr<SshMessageMiddleware> open_hijacked_channel_middleware_;
  Envoy::Event::TimerPtr stats_timer_;
};

class UpstreamConnectionService final : public ConnectionService,
                                        public UpstreamService {
public:
  UpstreamConnectionService(UpstreamTransportCallbacks& callbacks)
      : ConnectionService(callbacks, Peer::Upstream) {}
  absl::Status requestService() override;
  absl::Status onServiceAccepted() override;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec