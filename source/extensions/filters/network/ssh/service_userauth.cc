#include "source/extensions/filters/network/ssh/service_userauth.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

UserAuthService::UserAuthService(ServerTransportCallbacks& callbacks, Api::Api& api)
    : callbacks_(callbacks), api_(api) {
  (void)callbacks_;
  (void)api_;
}

std::string UserAuthService::name() const { return "ssh-userauth"; }

error UserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::UserAuthRequest: {

    UserAuthBannerMsg banner{};
    banner.message = "beans";
    callbacks_.downstream().sendMessage(banner);
    return callbacks_.downstream().sendMessage(EmptyMsg<SshMessageType::UserAuthSuccess>());
  }
  default:
    // specific protocols
    break;
  }
  return std::nullopt;
}

void UserAuthService::registerMessageHandlers(MessageDispatcher& dispatcher) {
  dispatcher.registerHandler(SshMessageType::UserAuthRequest, this);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec