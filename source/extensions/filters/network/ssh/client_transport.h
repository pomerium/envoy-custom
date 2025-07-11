#pragma once

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
                                 public UpstreamTransportCallbacks,
                                 public SshMessageMiddleware {
public:
  SshClientTransport(Api::Api& api,
                     std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config);
  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override;

  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) final;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) final;

  absl::Status handleMessage(wire::Message&& msg) override;
  AuthState& authState() override;
  void forward(wire::Message&& msg, FrameTags tags = EffectiveCommon) override;
  void forwardHeader(wire::Message&& msg, FrameTags tags = {}) override;

  absl::StatusOr<size_t> sendMessageToConnection(wire::Message&& msg) override;

  stream_id_t streamId() const override;

protected:
  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override;
  void onDecodingFailure(absl::Status err) override;

private:
  void initServices();
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& ssh_msg) override;

  AuthStateSharedPtr downstream_state_;
  std::unique_ptr<UpstreamUserAuthService> user_auth_svc_;
  std::unique_ptr<UpstreamConnectionService> connection_svc_;
  std::unique_ptr<PingExtensionHandler> ping_handler_;

  std::map<std::string, UpstreamService*> services_;

  bool channel_id_remap_enabled_{false};
  bool upstream_is_direct_tcpip_{false};
  bool response_stream_header_sent_{false};

  // translates upstream channel ids from {the id the downstream thinks the upstream has} -> {the id the upstream actually has}
  std::unordered_map<uint32_t, uint32_t> channel_id_mappings_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec