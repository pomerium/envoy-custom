#pragma once

#include <string>
#include "source/extensions/filters/network/ssh/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Service {
public:
  virtual ~Service() = default;
  virtual std::string name() const PURE;
  virtual bool acceptsMessage(SshMessageType msgType) const PURE;
  virtual error handleMessage(AnyMsg&& msg) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec