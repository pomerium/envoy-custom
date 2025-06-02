#pragma once

#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class PingExtensionHandler : public SshMessageHandler,
                                       public Logger::Loggable<Logger::Id::filter> {
public:
  PingExtensionHandler(TransportCallbacks& transport);

  absl::Status handleMessage(wire::Message&& msg) override;
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  void enableForward(bool enable);

private:
  TransportCallbacks& transport_;
  bool forward_{false};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec