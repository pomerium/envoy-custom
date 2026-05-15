#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#pragma clang unsafe_buffer_usage begin
#include "envoy/event/dispatcher.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ChannelFilter {
public:
  virtual ~ChannelFilter() = default;
  // Called just before a message is about to be forwarded to the peer.
  virtual void onMessageForward(const wire::Message& msg) PURE;
};

class ReadDisableHandle {
public:
  virtual ~ReadDisableHandle() = default;
};

using ReadDisableHandlePtr = std::unique_ptr<ReadDisableHandle>;

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

  // Returns this channel's stream ID.
  virtual stream_id_t streamId() const PURE;

  // Returns this connection's auth info.
  virtual const AuthInfo& authInfo() const PURE;

  // Returns this connection's dispatcher. The dispatcher may be obtained from either the upstream
  // or downstream connection depending on the direction of this channel, but both dispatchers
  // will be for the same thread.
  virtual Envoy::Event::Dispatcher& connectionDispatcher() const PURE;

  // Temporarily disable reads for the connection until the returned handle is destroyed. This can
  // be used to apply backpressure if the filter can't keep up, to avoid blocking the worker thread.
  // It is strongly recommended to accompany this with a separate timer to avoid keeping the
  // connection disabled for too long.
  //
  // TODO: this is a bit of a hack. The proper way to support this would be to suppress channel
  // window updates (the way it is handled for reverse tunnels), but we currently don't manage flow
  // control ourselves for normal channels.
  [[nodiscard]]
  virtual ReadDisableHandlePtr connectionReadDisable() PURE;
};

using ChannelFilterPtr = std::unique_ptr<ChannelFilter>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
