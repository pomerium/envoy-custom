#pragma once

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
};

using StreamCallbacksSharedPtr = std::shared_ptr<StreamCallbacks>;
using StreamCallbacksWeakPtr = std::weak_ptr<StreamCallbacks>;

class StreamInterface {
public:
  StreamInterface(stream_id_t stream_id, Network::Connection& connection, StreamCallbacksWeakPtr callbacks);

  stream_id_t streamId() { return stream_id_; }

private:
  stream_id_t stream_id_;
  Thread::ThreadId source_thread_;
  StreamCallbacksWeakPtr callbacks_;
  ::Envoy::Event::Dispatcher& source_dispatcher_;
};
using StreamInterfaceSharedPtr = std::shared_ptr<StreamInterface>;
using StreamInterfaceWeakPtr = std::weak_ptr<StreamInterface>;

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
  virtual void onStreamBegin(StreamInterface& intf) PURE;
  virtual void onStreamEnd(StreamInterface& intf) PURE;
};

using StreamTrackerFilterPtr = std::unique_ptr<StreamTrackerFilter>;
using StreamTrackerFilterMap = std::unordered_map<std::string, StreamTrackerFilterPtr>;

class StreamTracker : public Singleton::Instance, public Logger::Loggable<Logger::Id::filter> {
public:
  static std::shared_ptr<StreamTracker> fromContext(Server::Configuration::ServerFactoryContext& context,
                                                    const StreamTrackerConfig& config);
  static std::shared_ptr<StreamTracker> fromContext(Server::Configuration::ServerFactoryContext& context);

  StreamInterfaceSharedPtr find(stream_id_t key) const;
  size_t numActiveConnectionHandles() const;

  [[nodiscard]]
  StreamHandlePtr onStreamBegin(stream_id_t stream_id, Network::Connection& connection, StreamCallbacksWeakPtr source_callbacks);
  void onStreamEnd(stream_id_t stream_id);

  const std::vector<StreamTrackerFilterPtr>& filtersForTest() { return filters_; }

private:
  StreamTracker(std::vector<StreamTrackerFilterPtr> listeners)
      : filters_(std::move(listeners)) {}

  const std::vector<StreamTrackerFilterPtr> filters_;

  mutable Thread::MutexBasicLockable mu_;
  absl::node_hash_map<stream_id_t, StreamInterfaceSharedPtr> ABSL_GUARDED_BY(mu_) active_connection_handles_;
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