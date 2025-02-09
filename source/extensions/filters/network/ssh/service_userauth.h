#pragma once
#include "messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/server_transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service, public MessageHandler {
public:
  UserAuthService(ServerTransportCallbacks& callbacks, Api::Api& api);
  std::string name() const override;
  absl::Status handleMessage(AnyMsg&& msg) override;
  void registerMessageHandlers(MessageDispatcher& dispatcher) override;

private:
  ServerTransportCallbacks& callbacks_;
  Api::Api& api_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec