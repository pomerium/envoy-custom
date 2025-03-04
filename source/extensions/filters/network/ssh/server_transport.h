#pragma once

#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/wire/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamUserAuthService;
class DownstreamConnectionService;

class SshServerCodec : public virtual Logger::Loggable<Logger::Id::filter>,
                       public TransportBase<ServerCodec>,
                       public DownstreamTransportCallbacks,
                       public StreamMgmtServerMessageHandler {
public:
  SshServerCodec(Api::Api& api,
                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                 CreateGrpcClientFunc create_grpc_client);

  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;

  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void initUpstream(AuthStateSharedPtr downstream_state) override;
  absl::StatusOr<bytes> signWithHostKey(bytes_view<> in) const override;
  const AuthState& authState() const override;
  AuthState& authState() override;
  void forward(std::unique_ptr<SSHStreamFrame> frame) override;

private:
  absl::Status handleMessage(wire::Message&& msg) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& msg) override;
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) const override {
    dispatcher.registerHandler(wire::SshMessageType::ServiceRequest, this);
    dispatcher.registerHandler(wire::SshMessageType::GlobalRequest, this);
    dispatcher.registerHandler(wire::SshMessageType::RequestSuccess, this);
    dispatcher.registerHandler(wire::SshMessageType::RequestFailure, this);
    dispatcher.registerHandler(wire::SshMessageType::Ignore, this);
    dispatcher.registerHandler(wire::SshMessageType::Debug, this);
    dispatcher.registerHandler(wire::SshMessageType::Unimplemented, this);
    dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
  }
  void registerMessageHandlers(
    MessageDispatcher<Grpc::ResponsePtr<ServerMessage>>& dispatcher) const override {
    dispatcher.registerHandler(ServerMessage::MessageCase::kStreamControl, this);
  }

  void sendMgmtClientMessage(const ClientMessage& msg) override;

  absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
  handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg);

  AuthStateSharedPtr downstream_state_;
  std::set<std::string> service_names_;
  std::unique_ptr<DownstreamUserAuthService> user_auth_service_;
  std::unique_ptr<DownstreamConnectionService> connection_service_;

  std::unique_ptr<StreamManagementServiceClient> mgmt_client_;
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec