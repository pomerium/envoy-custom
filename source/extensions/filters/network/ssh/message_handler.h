#pragma once

#include <unordered_map>
#include <utility>

#pragma clang unsafe_buffer_usage begin
#include "absl/status/status.h"
#include "source/common/common/assert.h"
#pragma clang unsafe_buffer_usage end
#include "fmt/format.h"

#include "envoy/common/pure.h"

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

enum MiddlewareResult {
  // Dispatch the message as normal.
  Continue = 0,
  // Do not dispatch the message and do not invoke any subsequent middlewares.
  Break = 1,
  // Uninstall this middleware. Used in combination with either Continue or Break.
  UninstallSelf = 2,
};

constexpr MiddlewareResult operator|(MiddlewareResult lhs, MiddlewareResult rhs) {
  return static_cast<MiddlewareResult>(std::to_underlying(lhs) | std::to_underlying(rhs));
}

template <typename T>
class MessageMiddleware {
public:
  virtual ~MessageMiddleware() = default;

  // Intercepts a message before it is dispatched to the corresponding message handler.
  //
  // This function must return either MiddlewareResult::Continue OR MiddlewareResult::Break, and
  // can optionally add the MiddlewareResult::UninstallSelf flag to uninstall itself.
  //
  // An error status will be treated the same way as in MessageHandler::handleMessage, resulting
  // in the connection being closed.
  //
  // Other message middlewares can be installed from within this callback, but they will not take
  // effect until the following message.
  virtual absl::StatusOr<MiddlewareResult> interceptMessage(T& msg) PURE;
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
  void registerHandler(message_case_type_t<T> message_type, MessageHandler<T>* handler) {
    if (dispatch_.contains(message_type)) {
      throw Envoy::EnvoyException(fmt::format("duplicate registration of message type: {}", message_type));
    }
    dispatch_[message_type] = handler;
  }

  void unregisterHandler(message_case_type_t<T> message_type) {
    dispatch_.erase(message_type);
  }

  void unregisterHandler(MessageHandler<T>* handler) {
    std::erase_if(dispatch_, [&handler](const auto& kv) {
      const auto& [_, v] = kv;
      return v == handler;
    });
  }

  // Installs a message middleware that will intercept all messages before they are dispatched to
  // the corresponding message handler.
  void installMiddleware(MessageMiddleware<T>* middleware) {
    middlewares_.push_back(middleware);
  }

protected:
  absl::Status dispatch(T&& msg) {
    if (!middlewares_.empty()) {
      auto last = std::prev(middlewares_.end());
      for (auto it = middlewares_.begin(); it != middlewares_.end() && std::prev(it) != last;) {
        auto r = (*it)->interceptMessage(msg);
        if (!r.ok()) {
          return r.status();
        }
        MiddlewareResult res = *r;
        if ((res & UninstallSelf) != 0) {
          it = middlewares_.erase(it);
        } else {
          it++;
        }
        if ((res & Break) != 0) {
          return absl::OkStatus();
        }
      }
    }

    message_case_type_t<T> mt = messageCase(msg);
    auto&& it = dispatch_.find(mt);
    if (it == dispatch_.end()) [[unlikely]] {
      return absl::InvalidArgumentError(fmt::format("message handler for type {}: unexpected message received: {}", type_name<T>(), mt));
    }
    return it->second->handleMessage(std::move(msg));
  }
  std::list<MessageMiddleware<T>*> middlewares_;
  std::unordered_map<message_case_type_t<T>, MessageHandler<T>*> dispatch_;
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