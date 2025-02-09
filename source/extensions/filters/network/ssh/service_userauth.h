#pragma once
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service, public MessageHandler {
public:
  UserAuthService(TransportCallbacks& callbacks, Api::Api& api);
  std::string name() const override;
  absl::Status handleMessage(AnyMsg&& msg) override;
  void registerMessageHandlers(MessageDispatcher& dispatcher) override;

private:
  TransportCallbacks& callbacks_;
  Api::Api& api_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec