#pragma once
#include "messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/server_transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public Service {
public:
  UserAuthService(ServerTransportCallbacks* callbacks, Api::Api& api);
  std::string name() const override;
  bool acceptsMessage(SshMessageType msgType) const override;
  error handleMessage(AnyMsg&& msg) override;

private:
  ServerTransportCallbacks* callbacks_{};
  Api::Api& api_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec