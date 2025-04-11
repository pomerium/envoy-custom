#pragma once

#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/shared.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamUserAuthService;
class DownstreamConnectionService;

class SshServerTransport final : public virtual Logger::Loggable<Logger::Id::filter>,
                                 public TransportBase<ServerCodec>,
                                 public DownstreamTransportCallbacks,
                                 public Network::ConnectionCallbacks,
                                 public StreamMgmtServerMessageHandler {
public:
  SshServerTransport(Api::Api& api,
                     std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                     CreateGrpcClientFunc create_grpc_client,
                     std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr);

  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;

  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void initUpstream(AuthStateSharedPtr downstream_state) override;
  absl::StatusOr<bytes> signWithHostKey(bytes_view in) const override;
  const AuthState& authState() const override;
  AuthState& authState() override;
  void forward(wire::Message&& message, FrameTags tags = EffectiveCommon) override;
  void onInitialKexDone() override;

  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  stream_id_t streamId() const override {
    return stream_id_;
  }

protected:
  void onDecodingFailure(absl::Status status) override;

private:
  void initServices();
  absl::Status handleMessage(wire::Message&& msg) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& msg) override;
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  void registerMessageHandlers(
    MessageDispatcher<Grpc::ResponsePtr<ServerMessage>>& dispatcher) override;

  void sendMgmtClientMessage(const ClientMessage& msg) override;

  absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
  handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg);

  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> tls_;
  AuthStateSharedPtr auth_state_;
  std::set<std::string> service_names_;
  std::unique_ptr<DownstreamUserAuthService> user_auth_service_;
  std::unique_ptr<DownstreamConnectionService> connection_service_;
  std::unique_ptr<DownstreamPingExtensionHandler> ping_handler_;

  std::unique_ptr<StreamManagementServiceClient> mgmt_client_;
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
  stream_id_t stream_id_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec