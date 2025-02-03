#include "source/extensions/filters/network/ssh/session.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

Session::Session(uint32_t channelId) : Channel(channelId) {}

error Session::handleRequest(const ChannelRequestMsg& msg) {
  (void)msg;
  return {"unimplemented"};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec