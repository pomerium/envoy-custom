#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;

class ConnectionService : public virtual Service,
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
  //
  //
  absl::StatusOr<uint32_t> startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id = std::nullopt);
  absl::Status handleMessage(wire::Message&& ssh_msg) override;
  absl::Status maybeStartPassthroughChannel(uint32_t internal_id);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;

  class ChannelCallbacksImpl final : public ChannelCallbacks,
                                     public LinkedObject<ChannelCallbacksImpl> {
  public:
    ChannelCallbacksImpl(ConnectionService& parent, uint32_t channel_id, Peer local_peer);
    absl::Status sendMessageLocal(wire::Message&& msg) override;
    absl::Status sendMessageRemote(wire::Message&& msg) override;
    uint32_t channelId() const override { return channel_id_; }
    void cleanup() override;

  private:
    ConnectionService& parent_;
    ChannelIDManager& channel_id_mgr_;
    const uint32_t channel_id_;
    const Peer local_peer_;
  };

protected:
  TransportCallbacks& transport_;
  const Peer local_peer_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;

  // field order is important: callbacks must not be destroyed before the channels are
  std::list<std::unique_ptr<ChannelCallbacksImpl>> channel_callbacks_;
  absl::flat_hash_map<uint32_t, std::unique_ptr<Channel>> channels_;
};

class HijackedChannelCallbacks {
public:
  virtual ~HijackedChannelCallbacks() = default;
  virtual void initHandoff(pomerium::extensions::ssh::SSHChannelControlAction_HandOffUpstream*) PURE;
  virtual void hijackedChannelFailed(absl::Status) PURE;
};

class DownstreamConnectionService final : public ConnectionService,
                                          public ChannelEventCallbacks {
  friend class OpenHijackedChannelMiddleware;

public:
  DownstreamConnectionService(TransportCallbacks& callbacks);

  void enableChannelHijack(HijackedChannelCallbacks& hijack_callbacks,
                           const pomerium::extensions::ssh::InternalTarget& config,
                           Envoy::Grpc::RawAsyncClientSharedPtr grpc_client);
  void disableChannelHijack();

private:
  DownstreamTransportCallbacks& transport_;

  std::unique_ptr<SshMessageMiddleware> open_hijacked_channel_middleware_;
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