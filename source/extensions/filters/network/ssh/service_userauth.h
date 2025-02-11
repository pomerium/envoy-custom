#pragma once
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service, public Logger::Loggable<Logger::Id::filter> {
public:
  constexpr virtual std::string name() override { return "ssh-userauth"; };
  UserAuthService(TransportCallbacks& callbacks, Api::Api& api);
  absl::Status handleMessage(AnyMsg&& msg) override;
  void registerMessageHandlers(MessageDispatcher& dispatcher) override;

  absl::Status requestService() override {
    ServiceRequestMsg req;
    req.service_name = name();
    return transport_.sendMessageToConnection(req).status();
  }

private:
  TransportCallbacks& transport_;
  Api::Api& api_;
  libssh::SshKeyPtr ca_user_key_;
  libssh::SshKeyPtr ca_user_pubkey_;
  std::unique_ptr<PubKeyUserAuthRequestMsg> pending_req_;
  libssh::SshKeyPtr pending_user_key_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec