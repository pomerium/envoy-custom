#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#pragma clang unsafe_buffer_usage begin
#include "source/common/common/thread.h"
#include "envoy/server/factory_context.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;
using Envoy::Event::FileReadyType;
using Envoy::Event::PlatformDefaultTriggerType;
using pomerium::extensions::ssh::StreamTrackerConfig;

class StreamCallbacks {
public:
  virtual ~StreamCallbacks() = default;
  virtual absl::StatusOr<uint32_t> startChannel(std::unique_ptr<Channel> channel, std::optional<uint32_t> channel_id = std::nullopt) PURE;
};

class StreamContext {
public:
  StreamContext(stream_id_t stream_id, Network::Connection& connection, StreamCallbacks& stream_callbacks, ChannelEventCallbacks& event_callbacks)
      : stream_id_(stream_id),
        connection_(connection),
        stream_callbacks_(stream_callbacks),
        event_callbacks_(event_callbacks) {}

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

class StreamHandle : public Cleanup {
public:
  StreamHandle(stream_id_t id, std::function<void()> f)
      : Cleanup(std::move(f)), id_(id) {}

  stream_id_t streamId() const { return id_; }

private:
  stream_id_t id_;
};
using StreamHandlePtr = std::unique_ptr<StreamHandle>;

class StreamTrackerFilter {
public:
  virtual ~StreamTrackerFilter() = default;
  virtual void onStreamBegin(StreamContext& ctx) PURE;
  virtual void onStreamEnd(StreamContext& ctx) PURE;
};
using StreamTrackerFilterPtr = std::unique_ptr<StreamTrackerFilter>;

class StreamTracker : public Singleton::Instance, public Logger::Loggable<Logger::Id::filter> {
public:
  static std::shared_ptr<StreamTracker> fromContext(Server::Configuration::ServerFactoryContext& context,
                                                    const StreamTrackerConfig& config);
  static std::shared_ptr<StreamTracker> fromContext(Server::Configuration::ServerFactoryContext& context);

  bool tryLock(stream_id_t key, std::function<void(StreamContext&)> cb);
  size_t numActiveConnectionHandles();

  [[nodiscard]]
  StreamHandlePtr onStreamBegin(stream_id_t stream_id, Network::Connection& connection,
                                StreamCallbacks& stream_callbacks, ChannelEventCallbacks& event_callbacks);
  void onStreamEnd(stream_id_t stream_id);

  size_t visitFiltersForTest(std::function<void(StreamTrackerFilter&)> cb) {
    Thread::LockGuard lock(mu_);
    for (auto& filter : filters_) {
      cb(*filter);
    }
    return filters_.size();
  }

private:
  StreamTracker() = default;
  void initialize(Server::Configuration::ServerFactoryContext& context,
                  const StreamTrackerConfig& config);

  Thread::MutexBasicLockable mu_;
  std::vector<StreamTrackerFilterPtr> filters_ ABSL_GUARDED_BY(mu_);
  absl::node_hash_map<stream_id_t, std::unique_ptr<StreamContext>> active_connection_handles_ ABSL_GUARDED_BY(mu_);
};
using StreamTrackerPtr = std::unique_ptr<StreamTracker>;
using StreamTrackerSharedPtr = std::shared_ptr<StreamTracker>;

class StreamTrackerFilterFactory : public Config::TypedFactory {
public:
  std::string category() const override { return "pomerium.ssh.stream_tracker.filters"; }

  virtual StreamTrackerFilterPtr createStreamTrackerFilter(
    const Protobuf::Message&, Server::Configuration::ServerFactoryContext&) PURE;
};
using StreamTrackerFilterFactoryPtr = std::unique_ptr<StreamTrackerFilterFactory>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec