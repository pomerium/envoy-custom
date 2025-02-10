#pragma once
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include <memory>

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static std::atomic_int32_t SessionIdCounter;

class Channel {
public:
  virtual ~Channel() = default;
  Channel(uint32_t channelId) : channel_id_(channelId) { (void)channel_id_; }
  virtual absl::Status handleRequest(const ChannelRequestMsg& msg) PURE;

protected:
  uint32_t channel_id_;
};

class ConnectionService : public Service {
public:
  constexpr virtual std::string name() override { return "ssh-connection"; };

  ConnectionService(TransportCallbacks& callbacks, Api::Api& api);
  absl::Status handleMessage(AnyMsg&& msg) override;
  void registerMessageHandlers(MessageDispatcher& dispatcher) override;

  static void RegisterChannelType(const std::string& name, auto create) {
    channelTypes[name] = create;
  }

  absl::Status requestService() override {
    ServiceRequestMsg req;
    req.service_name = name();
    return transport_.sendMessageToConnection(req).status();
  }

private:
  TransportCallbacks& transport_;
  Api::Api& api_;

  std::map<uint32_t, std::unique_ptr<Channel>> active_channels_;

  static std::map<std::string, std::function<std::unique_ptr<Channel>(uint32_t)>> channelTypes;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec