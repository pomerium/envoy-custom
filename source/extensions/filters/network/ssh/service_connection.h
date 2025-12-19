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

    [[nodiscard]]
    Envoy::Common::CallbackHandlePtr addInterruptCallback(std::function<void(absl::Status, TransportCallbacks& transport)> cb) override;

    // Initiates a channel close from Envoy. This will propagate to both peers and close the channel
    // as normal.
    // This is not part of the ChannelCallbacks interface; it is only used by ConnectionService.
    //
    // The sequence of events for an internal close is as follows:
    // 1. Envoy sends a ChannelClose message to the local peer.
    // 2. The local peer replies with its own ChannelClose message.
    // 3. The local Channel receives the close message, and sends a ChannelClose message of its
    //    own to the remote peer (if one exists).
    // 4. The local Channel is destroyed, and invokes ChannelCallbacks::cleanup(), which releases
    //    the channel id and marks the channel as closed internally.
    // 5. The remote peer receives the ChannelClose message (sent in step 3) and replies with a
    //    ChannelClose message of its own.
    // 6. The remote channel processes the ChannelClose message, and sends one to its peer
    //    (the local peer from our perspective).
    //    Note: at this point, the local channel thinks it has already received a ChannelClose
    //    from its remote peer, so the real local client will have actually closed that channel
    //    and we can't send anything to it. The internal ID is still half-released though.
    // 7. The remote peer transport requests the ChannelIDManager to process its outgoing
    //    ChannelClose message (sent in step 6), and the ChannelIDManager returns
    //    a flag indicating the message should be dropped. The message is dropped.
    // 8. The remote peer's Channel is destroyed, and its channel ID is released. Both sides
    //    are now released, so the internal channel is freed.
    //
    // Note: in the shutdown() case, all local channels are closed at the same time. This usually
    // results in the local client sending a DisconnectMsg after the last channel is closed. When
    // that happens, the upstream is reset immediately and the sequence above skips over steps
    // 5-7, and step 8 happens when the filter chain is destroyed, while parent_.channel_callbacks_
    // is being deleted.
    void internalClose(absl::Status err);

  private:
    void cleanup() override;
    ConnectionService& parent_;
    ChannelIDManager& channel_id_mgr_;
    const uint32_t channel_id_;
    const Peer local_peer_;
    Stats::ScopeSharedPtr scope_;
    Envoy::Event::TimerPtr close_timer_;
    Envoy::OptRef<ChannelStatsProvider> stats_provider_;
    Envoy::Common::CallbackManager<void, absl::Status, TransportCallbacks&> interrupt_callbacks_;
    bool closed_internally_{false};
  };

protected:
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
  virtual void hijackedChannelFailed(absl::Status) PURE;
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