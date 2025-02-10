#pragma once

#include <string>
#include <type_traits>
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/message_handler.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Service : public MessageHandler {
public:
  virtual ~Service() = default;
  constexpr virtual std::string name() PURE;
  // called after initial handshake and key exchange
  virtual absl::Status requestService() PURE;
  virtual void registerMessageHandlers(MessageDispatcher& dispatcher) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec