#pragma once

#ifdef SSH_EXPERIMENTAL
#include <memory>

#pragma clang unsafe_buffer_usage begin
#include "envoy/thread_local/thread_local.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/experimental.h"
#include "source/extensions/filters/network/ssh/vt_buffer.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using ::Envoy::Event::Dispatcher;

// Upstream
class SourceUpstreamSessionMultiplexer : public SourceCallbacks,
                                         public std::enable_shared_from_this<SourceUpstreamSessionMultiplexer>,
                                         public virtual Logger::Loggable<Logger::Id::filter> {
public:
  SourceUpstreamSessionMultiplexer(
    Api::Api& api,
    TransportCallbacks& transport,
    ThreadLocalDataSlotSharedPtr tls,
    Dispatcher& dispatcher);

  absl::Status onStreamBegin(const AuthState& auth_state);
  void onStreamEnd();
  absl::Status handleUpstreamToDownstreamMessage(wire::Message& msg);
  void updateSource(const wire::ChannelDataMsg& msg);

  void onMirrorAdded(std::weak_ptr<MirrorCallbacks> mc) override;
  void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) override;

  // SourceInterface
  void inject(wire::ChannelDataMsg&& msg) override;
  void resize(const wire::WindowDimensionChangeChannelRequestMsg& msg) override;

private:
  Api::Api& api_;
  TransportCallbacks& transport_;

  Codec::MultiplexingInfo info_;
  std::optional<uint64_t> current_stream_id_;
  ThreadLocalDataSlotSharedPtr tls_;
  Dispatcher& local_dispatcher_;
  bool stream_ending_{false};
  std::set<std::weak_ptr<MirrorCallbacks>, std::owner_less<>> active_mirrors_;
  std::shared_ptr<VTCurrentStateTracker> vt_state_;
};

// Downstream
class SourceDownstreamSessionMultiplexer : public SourceInterfaceCallbacks {
public:
  void onStreamEnd();
  void setSourceInterface(std::weak_ptr<SourceInterface> si) override;
  absl::Status handleDownstreamToUpstreamMessage(wire::Message& msg);

private:
  std::optional<std::weak_ptr<SourceInterface>> source_interface_;
  bool stream_ending_{false};
};

// Downstream
class MirrorSessionMultiplexer : public MirrorCallbacks,
                                 public VTBufferCallbacks,
                                 public std::enable_shared_from_this<MirrorSessionMultiplexer>,
                                 public virtual Logger::Loggable<Logger::Id::filter> {
public:
  MirrorSessionMultiplexer(
    Api::Api& api,
    TransportCallbacks& transport,
    ThreadLocalDataSlotSharedPtr tls,
    Dispatcher& dispatcher);

  absl::Status onStreamBegin(const AuthState& auth_state);
  absl::Status handleDownstreamToUpstreamMessage(wire::Message& msg);

  // MirrorCallbacks
  void sendMsg(wire::Message&& msg) override;
  void onUpdate(Envoy::Buffer::Instance& buf) override;
  void onSourceResized(int width, int height) override;
  void onStreamEnd(const std::string& msg) override;

private:
  Api::Api& api_;
  TransportCallbacks& transport_;
  bool stream_ending_{false};

  Codec::MultiplexingInfo info_;
  std::optional<uint64_t> current_stream_id_;
  ThreadLocalDataSlotSharedPtr tls_;
  Dispatcher& local_dispatcher_;
  std::weak_ptr<SourceInterface> source_interface_;
  std::optional<uint32_t> sender_channel_;
  std::unique_ptr<VTBuffer> vt_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

#endif