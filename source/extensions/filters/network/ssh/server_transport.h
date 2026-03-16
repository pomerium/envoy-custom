#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/extension_ping.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/service_connection.h"

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
                     StreamTrackerSharedPtr active_stream_tracker,
                     const SecretsProvider& secrets_provider);

  void onConnected() override;

  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void onServiceAuthenticated(const std::string& service_name) override;
  void initUpstream(AuthInfoSharedPtr auth_info) override;
  AuthInfo& authInfo() override;
  void forward(wire::Message&& message, FrameTags tags = EffectiveCommon) override;
  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override;

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;
  void sendMgmtClientMessage(const ClientMessage& msg) override;

  stream_id_t streamId() const override { return stream_id_; }

  ChannelIDManager& channelIdManager() override { return *channel_id_manager_; }

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
  pomerium::extensions::ssh::InternalCLIModeHint modeHint() const override;

private:
  void initServices();
  bool upstreamReady() const { return auth_info_ != nullptr; }

  absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
  handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg);

  bool respond_called_{};
  bool received_port_forward_request_{};
  bool been_terminated_{};
  stream_id_t stream_id_{};
  AuthInfoSharedPtr auth_info_;

  Envoy::OptRef<Envoy::Event::Dispatcher> connection_dispatcher_;
  std::shared_ptr<ChannelIDManager> channel_id_manager_;
  std::unique_ptr<PingExtensionHandler> ping_handler_;
  StreamTrackerSharedPtr stream_tracker_;

  std::unique_ptr<StreamManagementServiceClient> mgmt_client_;
  std::shared_ptr<ChannelStreamServiceClient> channel_client_;
  std::shared_ptr<Envoy::Grpc::RawAsyncClient> grpc_client_;

  std::map<std::string, Service*> services_;
  std::unique_ptr<DownstreamUserAuthService> user_auth_service_;
  std::unique_ptr<DownstreamConnectionService> connection_service_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec