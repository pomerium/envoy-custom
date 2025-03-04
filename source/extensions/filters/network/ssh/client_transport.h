#pragma once

#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include <unordered_map>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UpstreamUserAuthService;
class UpstreamConnectionService;

class SshClientCodec : public virtual Logger::Loggable<Logger::Id::filter>,
                       public TransportBase<ClientCodec>,
                       public SshMessageMiddleware {
public:
  SshClientCodec(Api::Api& api,
                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config);

  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;

  absl::Status handleMessage(wire::Message&& msg) override;
  absl::StatusOr<bytes> signWithHostKey(bytes_view<> in) const override;
  const AuthState& authState() const override;
  AuthState& authState() override;
  void forward(std::unique_ptr<SSHStreamFrame> frame) override;

protected:
  void onInitialKexDone() override;

private:
  void writeToConnection(Envoy::Buffer::Instance& buf) const override;
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) const override;
  bool interceptMessage(wire::Message& ssh_msg) override;

  AuthStateSharedPtr downstream_state_;
  std::unique_ptr<UpstreamUserAuthService> user_auth_svc_;
  std::unique_ptr<UpstreamConnectionService> connection_svc_;
  std::map<std::string, Service*> services_;

  bool channel_id_remap_enabled_{false};

  // translates upstream channel ids from {the id the downstream thinks the upstream has} -> {the id the upstream actually has}
  std::unordered_map<uint32_t, uint32_t> channel_id_mappings_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec