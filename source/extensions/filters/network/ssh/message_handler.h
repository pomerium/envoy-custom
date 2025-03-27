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
  virtual void registerMessageHandlers(MessageDispatcher<T>& dispatcher) PURE;
};

template <typename T>
class MessageMiddleware {
public:
  virtual ~MessageMiddleware() = default;

  // A return value of true indicates the message should continue to be processed as normal.
  // A return value of false indicates the message should be dropped immediately. Subsequent
  // middleware handlers will not be called.
  // An error status will be treated the same way as in MessageHandler::handleMessage, resulting
  // in the connection being closed.
  virtual absl::StatusOr<bool> interceptMessage(T& msg) PURE;
};

template <typename T>
struct message_case_type;

template <typename T>
using message_case_type_t = message_case_type<T>::type;

template <typename T>
message_case_type_t<T> messageCase(const T& msg);

template <typename T>
struct HandlerInfo {
  MessageHandler<T>* handler;
  bool enabled{};
};

template <typename T>
class MessageDispatcher {
public:
  void registerHandler(message_case_type_t<T> message_type, MessageHandler<T>* handler) {
    if (dispatch_.contains(message_type)) {
      PANIC("bug: duplicate registration of message type");
    }
    dispatch_[message_type] = HandlerInfo{
      .handler = handler,
      .enabled = true,
    };
  }

  void unregisterHandler(message_case_type_t<T> message_type) {
    dispatch_.erase(message_type);
  }

  void installMiddleware(MessageMiddleware<T>* middleware) {
    middlewares_.push_back(middleware);
  }

  void uninstallMiddleware(MessageMiddleware<T>* middleware) {
    middlewares_.remove(middleware);
  }

  void setHandlerEnabled(MessageHandler<T>* handler, bool enabled) {
    for (auto&& [k, v] : dispatch_) {
      if (v.handler == handler) {
        v.enabled = enabled;
      }
    }
  }

protected:
  absl::Status dispatch(T&& msg) {
    for (auto& mw : middlewares_) {
      auto cont = mw->interceptMessage(msg);
      if (!cont.ok()) [[unlikely]] {
        return cont.status();
      }
      if (!*cont) {
        return absl::OkStatus();
      }
    }

    message_case_type_t<T> mt = messageCase(msg);
    auto&& it = dispatch_.find(mt);
    if (it == dispatch_.end()) [[unlikely]] {
      return absl::Status(absl::StatusCode::kInternal, fmt::format("unknown message type: {}", mt));
    }
    if (it->second.enabled) {
      return it->second.handler->handleMessage(std::move(msg));
    }
    return absl::OkStatus();
  }
  std::list<MessageMiddleware<T>*> middlewares_;
  std::unordered_map<message_case_type_t<T>, HandlerInfo<T>> dispatch_;
};

using SshMessageDispatcher = MessageDispatcher<wire::Message>;
using SshMessageHandler = MessageHandler<wire::Message>;
using SshMessageMiddleware = MessageMiddleware<wire::Message>;

template <>
struct message_case_type<wire::Message> : std::type_identity<wire::SshMessageType> {};

template <>
inline wire::SshMessageType messageCase(const wire::Message& msg) {
  return msg.msg_type();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec