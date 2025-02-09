#include "source/extensions/filters/network/ssh/session.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

Session::Session(uint32_t channelId) : Channel(channelId) {}

absl::Status Session::handleRequest(const ChannelRequestMsg& msg) {
  (void)msg;
  return absl::UnimplementedError("unimplemented");
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec