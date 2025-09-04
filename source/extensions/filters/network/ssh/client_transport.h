#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/extension_ping.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport_base.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UpstreamUserAuthService;
class UpstreamConnectionService;

class HandoffChannelCallbacks {
public:
  virtual ~HandoffChannelCallbacks() = default;
  virtual void onHandoffComplete() PURE;
};

class SshClientTransport final : public TransportBase<ClientCodec>,
                                 public HandoffChannelCallbacks,
                                 public UpstreamTransportCallbacks {
  friend class HandoffMiddleware;

public:
  SshClientTransport(Envoy::Server::Configuration::ServerFactoryContext& context,
                     std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config);
  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override;

  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) final;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) final;

  absl::Status handleMessage(wire::Message&& msg) override;
  AuthState& authState() override;
  void forward(wire::Message&& msg, FrameTags tags = EffectiveCommon) override;
  void forwardHeader(wire::Message&& msg, FrameTags tags = {}) override;

  stream_id_t streamId() const override;

  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override {
    ASSERT(callbacks_->connection().has_value());
    return callbacks_->connection()->dispatcher();
  }

  ChannelIDManager& channelIdManager() override {
    ASSERT(channel_id_manager_ != nullptr);
    return *channel_id_manager_;
  }

  void onHandoffComplete() override {
    // handoff is complete, send an empty message to signal the downstream codec
    forwardHeader(wire::IgnoreMsg{}, Sentinel);
  }

protected:
  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override;
  void terminate(absl::Status err) override;

private:
  void initServices();
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;

  AuthStateSharedPtr auth_state_;
  std::unique_ptr<UpstreamUserAuthService> user_auth_svc_;
  std::unique_ptr<UpstreamConnectionService> connection_svc_;
  std::unique_ptr<PingExtensionHandler> ping_handler_;
  std::unique_ptr<Envoy::Event::DeferredDeletable> handoff_middleware_;
  std::shared_ptr<ChannelIDManager> channel_id_manager_; // shared with downstream

  std::map<std::string, UpstreamService*> services_;

  bool upstream_is_direct_tcpip_{false};
  bool response_stream_header_sent_{false};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec