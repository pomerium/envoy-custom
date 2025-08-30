#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/extension_ping.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport_base.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamUserAuthService;
class DownstreamConnectionService;

class SshServerTransport final : public TransportBase<ServerCodec>,
                                 public Network::ConnectionCallbacks,
                                 public DownstreamTransportCallbacks,
                                 public HijackedChannelCallbacks {
public:
  SshServerTransport(Server::Configuration::ServerFactoryContext& context,
                     std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                     CreateGrpcClientFunc create_grpc_client,
                     StreamTrackerSharedPtr active_stream_tracker);

  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;
  void onConnected() override;

  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void onServiceAuthenticated(const std::string& service_name) override;
  void initUpstream(AuthStateSharedPtr downstream_state) override;
  AuthState& authState() override;
  void forward(wire::Message&& message, FrameTags tags = EffectiveCommon) override;
  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override;

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;
  void sendMgmtClientMessage(const ClientMessage& msg) override;

  stream_id_t streamId() const override { return stream_id_; }

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}
  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override {
    return connection_dispatcher_;
  }
  void terminate(absl::Status status) override;

  // HijackedChannelCallbacks
  void initHandoff(pomerium::extensions::ssh::SSHChannelControlAction_HandOffUpstream* handoff_msg) override;
  void hijackedChannelFailed(absl::Status err) override {
    terminate(err);
  }

private:
  void initServices();

  bool upstreamReady() const { return auth_state_ != nullptr; };

  absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
  handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg);

  AuthStateSharedPtr auth_state_;
  std::map<std::string, Service*> services_;
  std::unique_ptr<DownstreamUserAuthService> user_auth_service_;
  std::unique_ptr<DownstreamConnectionService> connection_service_;
  std::unique_ptr<PingExtensionHandler> ping_handler_;

  std::unique_ptr<StreamManagementServiceClient> mgmt_client_;
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
  std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client_;
  stream_id_t stream_id_;

  Envoy::OptRef<Envoy::Event::Dispatcher> connection_dispatcher_;
  StreamTrackerSharedPtr stream_tracker_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec