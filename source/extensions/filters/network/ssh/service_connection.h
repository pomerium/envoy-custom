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
  void onServerDraining(std::chrono::milliseconds delay) final {
    ENVOY_LOG(debug, "ssh: stream {}: handling graceful shutdown (delay: {})", transport_.streamId(), delay);
    runInterruptCallbacks(absl::UnavailableError("server shutting down"));
    transport_.terminate(absl::UnavailableError("server shutting down"));
  }
  size_t runInterruptCallbacks(absl::Status status) {
    auto n = interrupt_callbacks_.size();
    ENVOY_LOG(debug, "ssh: stream {}: running {} interrupt callbacks", transport_.streamId(), n);
    interrupt_callbacks_.runCallbacks(status, transport_);
    return n;
  }
  absl::Status handleMessage(wire::Message&& ssh_msg) override;
  absl::Status maybeStartPassthroughChannel(uint32_t internal_id);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;

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
    Envoy::Common::CallbackHandlePtr addInterruptCallback(std::function<void(absl::Status, TransportCallbacks& transport)> cb) final {
      return parent_.interrupt_callbacks_.add(std::move(cb));
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
  };

protected:
  TransportCallbacks& transport_;
  const Peer local_peer_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;

  // field order is important: callbacks must not be destroyed before the channels are
  std::list<std::unique_ptr<ChannelCallbacksImpl>> channel_callbacks_;
  absl::flat_hash_map<uint32_t, std::unique_ptr<Channel>> channels_;
  Envoy::Common::CallbackManager<void, absl::Status, TransportCallbacks&> interrupt_callbacks_;
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