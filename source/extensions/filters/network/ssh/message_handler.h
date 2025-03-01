#pragma once
#include <unordered_map>
#include <utility>

#include "absl/status/status.h"
#include "fmt/format.h"

#include "envoy/common/pure.h"
#include "source/common/common/assert.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

template <typename T>
class MessageDispatcher;

template <typename T>
class MessageHandler {
public:
  virtual ~MessageHandler() = default;
  virtual absl::Status handleMessage(T&& msg) PURE;
  virtual void registerMessageHandlers(MessageDispatcher<T>& dispatcher) const PURE;
};

template <typename T>
class MessageMiddleware {
public:
  virtual ~MessageMiddleware() = default;
  virtual bool interceptMessage(T& msg) PURE;
};

template <typename T>
struct message_case_type;

template <typename T>
using message_case_type_t = message_case_type<T>::type;

template <typename T>
message_case_type_t<T> messageCase(const T& msg);

template <typename T>
class MessageDispatcher {
public:
  void registerHandler(message_case_type_t<T> message_type, const MessageHandler<T>* handler) {
    if (dispatch_.contains(message_type)) {
      PANIC("bug: duplicate registration of message type");
    }
    dispatch_[message_type] = const_cast<MessageHandler<T>*>(handler);
  }

  void unregisterHandler(message_case_type_t<T> message_type) {
    dispatch_.erase(message_type);
  }

  void installMiddleware(MessageMiddleware<T>* middleware) {
    middlewares_.push_back(middleware);
  }

  void uninstallMiddleware(MessageMiddleware<T>* middleware) {
    if (auto it = std::find(middlewares_.begin(), middlewares_.end(), middleware);
        it != middlewares_.end()) {
      middlewares_.erase(it);
    }
  }

protected:
  absl::Status dispatch(T&& msg) {
    message_case_type_t<T> mt = messageCase(msg);
    if (!dispatch_.contains(mt)) {
      return absl::Status(absl::StatusCode::kInternal, fmt::format("unknown message type: {}", mt));
    }
    if (!middlewares_.empty()) {
      for (auto& mw : middlewares_) {
        auto cont = mw->interceptMessage(msg);
        if (!cont) {
          return absl::OkStatus();
        }
      }
    }
    return dispatch_[mt]->handleMessage(std::move(msg));
  }
  std::list<MessageMiddleware<T>*> middlewares_;
  std::unordered_map<message_case_type_t<T>, MessageHandler<T>*> dispatch_;
};

using SshMessageDispatcher = MessageDispatcher<wire::SshMsg>;
using SshMessageHandler = MessageHandler<wire::SshMsg>;
using SshMessageMiddleware = MessageMiddleware<wire::SshMsg>;

template <>
struct message_case_type<wire::SshMsg> : std::type_identity<wire::SshMessageType> {};

template <>
inline wire::SshMessageType messageCase(const wire::SshMsg& msg) {
  return msg.msg_type();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec