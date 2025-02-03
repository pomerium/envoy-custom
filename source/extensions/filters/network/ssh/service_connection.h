#pragma once
#include "messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/server_transport.h"
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
  virtual error handleRequest(const ChannelRequestMsg& msg) PURE;

protected:
  uint32_t channel_id_;
};

class ConnectionService : public Service {
public:
  ConnectionService(ServerTransportCallbacks* callbacks, Api::Api& api);
  std::string name() const override;

  bool acceptsMessage(SshMessageType msgType) const override;

  error handleMessage(AnyMsg&& msg) override;

  static void RegisterChannelType(const std::string& name, auto create) {
    channelTypes[name] = create;
  }

private:
  ServerTransportCallbacks* callbacks_{};
  Api::Api& api_;

  std::map<uint32_t, std::unique_ptr<Channel>> active_channels_;

  static std::map<std::string, std::function<std::unique_ptr<Channel>(uint32_t)>> channelTypes;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec