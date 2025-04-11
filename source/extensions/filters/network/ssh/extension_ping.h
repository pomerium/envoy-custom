#pragma once

#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamPingExtensionHandler : public SshMessageHandler,
                                       public Logger::Loggable<Logger::Id::filter> {
public:
  DownstreamPingExtensionHandler(TransportCallbacks& transport)
      : transport_(transport) {}

  absl::Status handleMessage(wire::Message&& msg) override {
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
        return transport_.sendMessageToConnection(reply).status();
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
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override {
    dispatcher.registerHandler(wire::SshMessageType::Ping, this);
    dispatcher.registerHandler(wire::SshMessageType::Pong, this);
  }

  void enableForward(bool enable) {
    forward_ = enable;
  }

private:
  TransportCallbacks& transport_;
  bool forward_{false};
};

class UpstreamPingExtensionHandler : public SshMessageHandler,
                                     public Logger::Loggable<Logger::Id::filter> {
public:
  UpstreamPingExtensionHandler(TransportCallbacks& transport)
      : transport_(transport) {}

  absl::Status handleMessage(wire::Message&& msg) override {
    return msg.visit(
      [&](wire::PingMsg& msg) {
        if (forward_) {
          // let the downstream handle the ping request
          transport_.forward(std::move(msg));
          return absl::OkStatus();
        }
        // send the reply ourselves
        wire::PongMsg reply;
        reply.data = msg.data;
        return transport_.sendMessageToConnection(reply).status();
      },
      [&](wire::PongMsg& msg) {
        if (forward_) {
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
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override {
    dispatcher.registerHandler(wire::SshMessageType::Ping, this);
    dispatcher.registerHandler(wire::SshMessageType::Pong, this);
  }

  void enableForward(bool enable) {
    forward_ = enable;
  }

private:
  TransportCallbacks& transport_;
  bool forward_{false};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec