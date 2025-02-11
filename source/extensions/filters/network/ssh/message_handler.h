#pragma once
#include "source/extensions/filters/network/ssh/messages.h"
#include <unordered_map>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class MessageHandler {
public:
  virtual ~MessageHandler() = default;
  virtual absl::Status handleMessage(AnyMsg&& msg) PURE;
};

class MessageDispatcher {
public:
  void registerHandler(SshMessageType messageType, MessageHandler* handler) {
    if (dispatch_.contains(messageType)) {
      PANIC("bug: duplicate registration of message type");
    }
    dispatch_[messageType] = handler;
  }

protected:
  absl::Status dispatch(AnyMsg&& msg) {
    auto mt = msg.msgtype;
    if (!dispatch_.contains(mt)) {
      return absl::Status(absl::StatusCode::kInternal, fmt::format("unknown message type: {}", mt));
    }
    return dispatch_[mt]->handleMessage(std::move(msg));
  }
  std::unordered_map<SshMessageType, MessageHandler*> dispatch_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec