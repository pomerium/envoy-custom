#pragma once

#include <string>

#include "source/extensions/filters/network/ssh/message_handler.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Service : public SshMessageHandler {
public:
  constexpr virtual std::string name() PURE;
  // called after initial handshake and key exchange
  virtual absl::Status requestService() PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec