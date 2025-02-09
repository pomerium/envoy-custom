#pragma once

#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class VersionExchangeCallbacks {
public:
  virtual ~VersionExchangeCallbacks() = default;
  virtual void setVersionStrings(const std::string& ours, const std::string& peer) PURE;
};

class VersionExchanger {
public:
  VersionExchanger(TransportCallbacks& callbacks, VersionExchangeCallbacks& handshakeCallbacks);
  absl::StatusOr<size_t> writeVersion(std::string_view ours);
  absl::Status readVersion(Envoy::Buffer::Instance& buffer);

protected:
  std::string their_version_;
  std::string our_version_;
  TransportCallbacks& transport_;
  VersionExchangeCallbacks& version_exchange_callbacks_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec