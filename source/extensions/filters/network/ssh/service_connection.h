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
  ConnectionService(ServerTransportCallbacks* callbacks, Api::Api& api)
      : callbacks_(callbacks), api_(api) {
    (void)callbacks_;
    (void)api_;
  }
  std::string name() const override { return "ssh-connection"; }

  bool acceptsMessage(SshMessageType msgType) const override {
    auto msgNum = static_cast<uint8_t>(msgType);
    return msgNum >= 80 && msgNum <= 127;
  }

  error handleMessage(AnyMsg&& msg) override {
    switch (msg.msg_type) {
    case SshMessageType::GlobalRequest:
      break;
    case SshMessageType::RequestSuccess:
      break;
    case SshMessageType::RequestFailure:
      break;
    case SshMessageType::ChannelOpen: {
      auto channelOpenMsg = msg.unwrap<ChannelOpenMsg>();
      auto newId = ++SessionIdCounter;
      if (channelTypes.contains(channelOpenMsg.channel_type)) {
        active_channels_[newId] = channelTypes[channelOpenMsg.channel_type](newId);
        ChannelOpenConfirmationMsg confirmation;
        confirmation.sender_channel = newId;
        confirmation.recipient_channel = channelOpenMsg.sender_channel;
        confirmation.initial_window_size = channelOpenMsg.initial_window_size;
        confirmation.max_packet_size = channelOpenMsg.max_packet_size;
        return callbacks_->downstream().sendMessage(confirmation);
      } else {
        ChannelOpenFailureMsg failure;
        failure.recipient_channel = channelOpenMsg.sender_channel;
        failure.reason_code = SSH2_OPEN_UNKNOWN_CHANNEL_TYPE;
        failure.description = "unknown channel type";
        return callbacks_->downstream().sendMessage(failure);
      }
      break;
    }
    case SshMessageType::ChannelOpenConfirmation:
      break;
    case SshMessageType::ChannelOpenFailure:
      break;
    case SshMessageType::ChannelWindowAdjust:
      break;
    case SshMessageType::ChannelData:
      break;
    case SshMessageType::ChannelExtendedData:
      break;
    case SshMessageType::ChannelEOF:
      break;
    case SshMessageType::ChannelClose:
      break;
    case SshMessageType::ChannelRequest: {
      auto channelRequestMsg = msg.unwrap<ChannelRequestMsg>();
      if (active_channels_.contains(channelRequestMsg.channel)) {
        return active_channels_[channelRequestMsg.channel]->handleRequest(channelRequestMsg);
      }
      break;
    }
    case SshMessageType::ChannelSuccess:
      break;
    case SshMessageType::ChannelFailure:
      break;
    default:
      break;
    }
    return std::nullopt;
  }

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