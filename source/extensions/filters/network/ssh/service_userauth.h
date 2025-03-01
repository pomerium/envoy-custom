#pragma once

#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service,
                        public Logger::Loggable<Logger::Id::filter> {
public:
  constexpr std::string name() override { return "ssh-userauth"; };
  UserAuthService(TransportCallbacks& callbacks, Api::Api& api);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) const override;
  absl::Status requestService() override;

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;
  openssh::SSHKey ca_user_key_;
  openssh::SSHKey ca_user_pubkey_;
  std::unique_ptr<wire::UserAuthRequestMsg> pending_req_;
  openssh::SSHKey pending_user_key_;
};

class DownstreamUserAuthService : public UserAuthService,
                                  public StreamMgmtServerMessageHandler {
public:
  DownstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api)
      : UserAuthService(callbacks, api),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)) {}

  using UserAuthService::registerMessageHandlers;
  absl::Status handleMessage(wire::SshMsg&& msg) override;

  void registerMessageHandlers(
      StreamMgmtServerMessageDispatcher& dispatcher) const override;
  absl::Status
  handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;

private:
  DownstreamTransportCallbacks& transport_;
};

class UpstreamUserAuthService : public UserAuthService {
public:
  using UserAuthService::UserAuthService;
  absl::Status handleMessage(wire::SshMsg&& msg) override;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec