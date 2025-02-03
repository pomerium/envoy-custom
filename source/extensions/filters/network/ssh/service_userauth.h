#pragma once
#include "messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/server_transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service {
public:
  UserAuthService(ServerTransportCallbacks* callbacks, Api::Api& api)
      : callbacks_(callbacks), api_(api) {
    (void)callbacks_;
    (void)api_;
  }
  std::string name() const override { return "ssh-userauth"; }

  bool acceptsMessage(SshMessageType msgType) const override {
    auto msgNum = static_cast<uint8_t>(msgType);
    return msgNum >= 50 && msgNum <= 79;
  }

  error handleMessage(AnyMsg&& msg) override {
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

private:
  ServerTransportCallbacks* callbacks_{};
  Api::Api& api_;
};
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec