#pragma once
#include <unordered_map>
#include <utility>

#include "absl/status/status.h"
#include "fmt/format.h"

#include "envoy/common/pure.h"
#include "source/common/common/assert.h"

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
struct message_case_type;

template <typename T>
using message_case_type_t = message_case_type<T>::type;

template <typename T>
message_case_type_t<T> messageCase(const T& msg);

template <typename T>
class MessageDispatcher {
public:
  void registerHandler(message_case_type_t<T> messageType, const MessageHandler<T>* handler) {
    if (dispatch_.contains(messageType)) {
      PANIC("bug: duplicate registration of message type");
    }
    dispatch_[messageType] = const_cast<MessageHandler<T>*>(handler);
  }

protected:
  absl::Status dispatch(T&& msg) {
    message_case_type_t<T> mt = messageCase(msg);
    if (!dispatch_.contains(mt)) {
      return absl::Status(absl::StatusCode::kInternal, fmt::format("unknown message type: {}", mt));
    }
    return dispatch_[mt]->handleMessage(std::forward<T>(msg));
  }
  std::unordered_map<message_case_type_t<T>, MessageHandler<T>*> dispatch_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec