#pragma once

#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/wire/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamUserAuthService;
class DownstreamConnectionService;

class SshServerCodec : public virtual Logger::Loggable<Logger::Id::filter>,
                       public ServerCodec,
                       public KexCallbacks,
                       public DownstreamTransportCallbacks,
                       public SshMessageDispatcher,
                       public SshMessageHandler,
                       public StreamMgmtServerMessageHandler {
public:
  SshServerCodec(Api::Api& api,
                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                 CreateGrpcClientFunc create_grpc_client,
                 AccessLog::AccessLogFileSharedPtr access_log);
  ~SshServerCodec() = default;
  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void setKexResult(std::shared_ptr<kex_result_t> kex_result) override;
  const kex_result_t& getKexResult() const override;
  void initUpstream(AuthStateSharedPtr downstreamState) override;
  absl::StatusOr<bytes> signWithHostKey(bytes_view<> in) const override;
  const AuthState& authState() const override;
  AuthState& authState() override;
  void forward(std::unique_ptr<SSHStreamFrame> frame) override;
  const pomerium::extensions::ssh::CodecConfig& codecConfig() const override;

private:
  absl::Status handleMessage(wire::SshMsg&& msg) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& msg) override;
  void registerMessageHandlers(MessageDispatcher<wire::SshMsg>& dispatcher) const override {
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

  const connection_state_t& getConnectionState() const override;
  void writeToConnection(Envoy::Buffer::Instance& buf) const override;
  void sendMgmtClientMessage(const ClientMessage& msg) override;
  absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
  handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg);

  GenericProxy::ServerCodecCallbacks* callbacks_{};
  bool version_exchange_done_{};
  std::unique_ptr<VersionExchanger> handshaker_;
  Api::Api& api_;

  std::unique_ptr<Kex> kex_;
  std::shared_ptr<kex_result_t> kex_result_;
  std::unique_ptr<connection_state_t> connection_state_;
  AuthStateSharedPtr downstream_state_;
  std::set<std::string> service_names_;
  std::unique_ptr<DownstreamUserAuthService> user_auth_service_;
  std::unique_ptr<DownstreamConnectionService> connection_service_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;

  std::unique_ptr<StreamManagementServiceClient> mgmt_client_;
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
  AccessLog::AccessLogFileSharedPtr access_log_;

  std::string server_version_{"SSH-2.0-Envoy"};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec