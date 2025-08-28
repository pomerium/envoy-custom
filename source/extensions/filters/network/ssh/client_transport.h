#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include <unordered_map>

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

class SshClientTransport final : public TransportBase<ClientCodec>,
                                 public UpstreamTransportCallbacks {
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
    auto connection = callbacks_->connection();
    if (!connection.has_value()) {
      return std::nullopt;
    }
    return connection->dispatcher();
  }

protected:
  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override;
  void terminate(absl::Status err) override;

private:
  class HandoffMiddleware : public SshMessageMiddleware, public HandoffChannelCallbacks {
  public:
    explicit HandoffMiddleware(SshClientTransport& self) : self_(self) {}
    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;
    void onHandoffComplete() override {
      // handoff is complete, send an empty message to signal the downstream codec
      self_.forwardHeader(wire::IgnoreMsg{}, Sentinel);
    }

  private:
    SshClientTransport& self_;
  };
  void initServices();
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;

  AuthStateSharedPtr auth_state_;
  std::unique_ptr<UpstreamUserAuthService> user_auth_svc_;
  std::unique_ptr<UpstreamConnectionService> connection_svc_;
  std::unique_ptr<PingExtensionHandler> ping_handler_;
  HandoffMiddleware handoff_middleware_{*this};

  std::map<std::string, UpstreamService*> services_;

  bool upstream_is_direct_tcpip_{false};
  bool response_stream_header_sent_{false};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec