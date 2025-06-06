#pragma once

#include <string>

#include "source/extensions/filters/network/ssh/message_handler.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Service : public SshMessageHandler {
public:
  virtual std::string name() PURE;
};

class UpstreamService : public virtual Service {
public:
  virtual ~UpstreamService() = default;

  // called after initial handshake and key exchange
  virtual absl::Status requestService() PURE;
  // called upon receipt of a ServiceAcceptedMsg
  virtual absl::Status onServiceAccepted() PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec