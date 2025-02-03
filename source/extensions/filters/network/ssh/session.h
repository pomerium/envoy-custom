#pragma once
#include "messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/service_connection.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Session : public Channel {
public:
  virtual ~Session() = default;
  Session(uint32_t channelId);
  error handleRequest(const ChannelRequestMsg& msg) override;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec