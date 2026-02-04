#pragma once

#include "absl/functional/any_invocable.h"
#pragma clang unsafe_buffer_usage begin
#include "envoy/event/dispatcher.h"
#include "envoy/server/factory_context.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class StreamCallbacks {
public:
  virtual ~StreamCallbacks() = default;
  virtual absl::StatusOr<uint32_t> startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id = std::nullopt) PURE;
  [[nodiscard]]
  virtual Envoy::Common::CallbackHandlePtr onServerDraining(std::chrono::milliseconds delay, Envoy::Event::Dispatcher& dispatcher, std::function<void()> complete_cb) PURE;
};

class StreamContext {
public:
  StreamContext(stream_id_t stream_id, Network::Connection& connection, StreamCallbacks& stream_callbacks, ChannelEventCallbacks& event_callbacks)
      : stream_id_(stream_id),
        connection_(connection),
        stream_callbacks_(stream_callbacks),
        event_callbacks_(event_callbacks) {}
  StreamContext(StreamContext&&) noexcept = default;
  StreamContext& operator=(StreamContext&&) noexcept = delete;
  StreamContext(const StreamContext&) = delete;
  StreamContext& operator=(const StreamContext&) = delete;

  stream_id_t streamId() { return stream_id_; }
  Network::Connection& connection() { return connection_; }
  StreamCallbacks& streamCallbacks() { return stream_callbacks_; }
  ChannelEventCallbacks& eventCallbacks() { return event_callbacks_; }

private:
  stream_id_t stream_id_;
  Network::Connection& connection_;
  StreamCallbacks& stream_callbacks_;
  ChannelEventCallbacks& event_callbacks_;
};

#define ALL_STREAM_TRACKER_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME) \
  COUNTER(total_streams)                                                            \
  GAUGE(active_streams, Accumulate)                                                 \
  STATNAME(ssh)

MAKE_STAT_NAMES_STRUCT(StreamTrackerStatNames, ALL_STREAM_TRACKER_STATS);
MAKE_STATS_STRUCT(StreamTrackerStats, StreamTrackerStatNames, ALL_STREAM_TRACKER_STATS);

class StreamHandle;
using StreamHandlePtr = std::unique_ptr<StreamHandle>;

class StreamTracker : public Singleton::Instance,
                      public std::enable_shared_from_this<StreamTracker>,
                      public Logger::Loggable<Logger::Id::filter> {
  friend class StreamHandle;

public:
  explicit StreamTracker(Server::Configuration::ServerFactoryContext& context);
  static std::shared_ptr<StreamTracker> fromContext(Server::Configuration::ServerFactoryContext& context);

  // If a stream with the given key is active, invokes the given callback in the stream's thread
  // with a valid StreamContext. Otherwise, invokes the callback with an empty context.
  // Does not block.
  void tryLock(stream_id_t key, absl::AnyInvocable<void(Envoy::OptRef<StreamContext>)> cb);

  // Adds the stream to the stream tracker, and returns a handle which removes the stream from
  // the stream tracker when deleted. The caller must arrange for the handle to live no longer than
  // the connection or the callback references passed to this function.
  // This function must be called from the same thread as the given connection, and the stream
  // handle must also be deleted in the same thread.
  [[nodiscard]] StreamHandlePtr onStreamBegin(stream_id_t stream_id,
                                              Network::Connection& connection,
                                              StreamCallbacks& stream_callbacks,
                                              ChannelEventCallbacks& event_callbacks,
                                              const std::function<void()>& on_sync_complete = nullptr);

  StreamTrackerStats& stats() { return stats_; }

private:
  class ThreadLocalStreamTable : public ThreadLocal::ThreadLocalObject {
  public:
    using StreamTable = absl::flat_hash_map<stream_id_t, std::variant<StreamContext, ::Envoy::Event::Dispatcher*>>;
    inline StreamTable& get() { return data_; }

  private:
    StreamTable data_;
  };

  void onStreamEnd(stream_id_t stream_id);
  void startGracefulShutdown(std::chrono::milliseconds delay, std::function<void()> complete_cb);

  ThreadLocal::TypedSlot<ThreadLocalStreamTable> thread_local_stream_table_;
  Envoy::Event::Dispatcher& main_thread_dispatcher_;

  Stats::Scope& scope_;
  StreamTrackerStatNames stat_names_;
  StreamTrackerStats stats_;
  Envoy::Server::ServerLifecycleNotifier::HandlePtr shutdown_cb_;
  Envoy::Common::CallbackHandlePtr drain_mgr_cb_;

  absl::Mutex drain_cb_mu_;
  std::unordered_map<stream_id_t, Envoy::Common::CallbackHandlePtr> channel_id_mgr_drain_cbs_ ABSL_GUARDED_BY(drain_cb_mu_);
  std::vector<Envoy::Event::PostCb> inflight_shutdown_guards_;
  bool shutdown_started_{false};
  bool shutdown_completed_{false};
};
using StreamTrackerPtr = std::unique_ptr<StreamTracker>;
using StreamTrackerSharedPtr = std::shared_ptr<StreamTracker>;

class StreamHandle {
  friend class StreamTracker;

public:
  ~StreamHandle();

  StreamHandle(StreamHandle&&) noexcept = default;
  StreamHandle& operator=(StreamHandle&&) noexcept = default;
  StreamHandle(const StreamHandle&) = delete;
  StreamHandle& operator=(const StreamHandle&) = delete;

  stream_id_t streamId() const { return id_; }

private:
  StreamHandle(stream_id_t id, std::weak_ptr<StreamTracker> parent);

  stream_id_t id_;
  std::weak_ptr<StreamTracker> parent_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec