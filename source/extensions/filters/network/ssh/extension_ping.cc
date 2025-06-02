#include "source/extensions/filters/network/ssh/extension_ping.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

PingExtensionHandler::PingExtensionHandler(TransportCallbacks& transport)
    : transport_(transport) {}
absl::Status PingExtensionHandler::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::PingMsg& msg) {
      if (forward_) {
        // let the upstream handle the ping request
        transport_.forward(std::move(msg));
        return absl::OkStatus();
      }
      // send the reply ourselves
      wire::PongMsg reply;
      reply.data = msg.data;
      return transport_.sendMessageToConnection(std::move(reply)).status();
    },
    [&](wire::PongMsg& msg) {
      if (forward_) {
        // openssh doesn't have servers initiate pings, but the spec doesn't say anything about it
        transport_.forward(std::move(msg));
        return absl::OkStatus();
      }
      ENVOY_LOG(info, "received pong: {}", msg.data);
      return absl::OkStatus();
    },
    [](auto&) {
      return absl::OkStatus();
    });
}

void PingExtensionHandler::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::Ping, this);
  dispatcher.registerHandler(wire::SshMessageType::Pong, this);
}

void PingExtensionHandler::enableForward(bool enable) {
  forward_ = enable;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec