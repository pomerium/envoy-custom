#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ChannelFilter {
public:
  virtual ~ChannelFilter() = default;
  // Called just before a message is about to be forwarded to the peer.
  virtual void onMessageForward(const wire::Message& msg) PURE;
};

class ChannelFilterCallbacks : public ChannelReadOnlyCallbacks {
public:
  virtual ~ChannelFilterCallbacks() = default;
  // Initiate a channel close sequence which will close the channel for all peers. All previously
  // registered interrupt callbacks (ChannelCallbacks::addInterruptCallback) will be invoked. The
  // provided error is passed to these callbacks.
  // Returns true if the connection was successfully interrupted, otherwise false. Some channel
  // states are not interruptable, for example if the channel is already in the process of being
  // closed.
  // This does not necessarily terminate the connection, but the downstream client may disconnect
  // if this was the last open channel. See ConnectionService::preempt for more details.
  virtual bool interruptChannel(absl::Status err) PURE;
};

using ChannelFilterPtr = std::unique_ptr<ChannelFilter>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
