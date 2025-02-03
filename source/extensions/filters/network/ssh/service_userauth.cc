#include "source/extensions/filters/network/ssh/service_userauth.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

UserAuthService::UserAuthService(ServerTransportCallbacks* callbacks, Api::Api& api)
    : callbacks_(callbacks), api_(api) {
  (void)callbacks_;
  (void)api_;
}

std::string UserAuthService::name() const { return "ssh-userauth"; }

bool UserAuthService::acceptsMessage(SshMessageType msgType) const {
  auto msgNum = static_cast<uint8_t>(msgType);
  return msgNum >= 50 && msgNum <= 79;
}

error UserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::UserAuthRequest:

    return callbacks_->downstream().sendMessage(EmptyMsg<SshMessageType::UserAuthSuccess>());
    break;
  case SshMessageType::UserAuthFailure:
    break;
  case SshMessageType::UserAuthSuccess:
    break;
  case SshMessageType::UserAuthBanner:
    break;
  default:
    // specific protocols
    break;
  }
  return std::nullopt;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec