#pragma once

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service,
                        public Logger::Loggable<Logger::Id::filter> {
public:
  constexpr std::string name() override { return "ssh-userauth"; };
  UserAuthService(TransportCallbacks& callbacks, Api::Api& api);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status requestService() override;

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;
  openssh::SSHKeyPtr ca_user_key_;
  std::unique_ptr<wire::UserAuthRequestMsg> pending_req_;
  openssh::SSHKeyPtr pending_user_key_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;
};

class DownstreamUserAuthService : public UserAuthService,
                                  public StreamMgmtServerMessageHandler {
public:
  DownstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api)
      : UserAuthService(callbacks, api),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)) {}

  using UserAuthService::registerMessageHandlers;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;

private:
  DownstreamTransportCallbacks& transport_;
};

class UpstreamUserAuthService final : public UserAuthService,
                                      public SshMessageMiddleware {
public:
  using UserAuthService::UserAuthService;
  absl::Status handleMessage(wire::Message&& msg) override;
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;

private:
  bool auth_success_received_{};
  std::optional<wire::ExtInfoMsg> ext_info_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec