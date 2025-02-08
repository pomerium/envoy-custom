#pragma once

#include <string>
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/message_handler.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Service {
public:
  virtual ~Service() = default;
  virtual std::string name() const PURE;

protected:
  virtual void registerMessageHandlers(MessageDispatcher& dispatcher) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec