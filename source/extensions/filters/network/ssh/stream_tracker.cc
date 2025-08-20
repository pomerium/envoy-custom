#include "source/extensions/filters/network/ssh/stream_tracker.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/config/utility.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SINGLETON_MANAGER_REGISTRATION(ssh_connection_tracker); // NOLINT

StreamInterface::StreamInterface(stream_id_t stream_id, Network::Connection& connection, std::weak_ptr<StreamCallbacks> source_callbacks)
    : stream_id_(stream_id),
      callbacks_(source_callbacks),
      source_dispatcher_(connection.dispatcher()) {}

StreamTrackerSharedPtr StreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context,
                                                  const pomerium::extensions::ssh::StreamTrackerConfig& config) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return context.singletonManager().getTyped<StreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_connection_tracker), [&] { // NOLINT
      std::vector<StreamTrackerFilterPtr> filters;
      for (const auto& filter_config : config.filters()) {
        auto& factory = Config::Utility::getAndCheckFactory<StreamTrackerFilterFactory>(filter_config);
        ProtobufTypes::MessagePtr message = factory.createEmptyConfigProto();
        THROW_IF_NOT_OK(Envoy::Config::Utility::translateOpaqueConfig(
          filter_config.typed_config(), context.messageValidationVisitor(), *message));
        filters.push_back(factory.createStreamTrackerFilter(*message, context));
      }
      return StreamTrackerSharedPtr(new StreamTracker(std::move(filters)));
    });
}

StreamTrackerSharedPtr StreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return context.singletonManager().getTyped<StreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_connection_tracker)); // NOLINT
}

StreamInterfaceSharedPtr StreamTracker::find(stream_id_t key) const {
  Thread::LockGuard lock(mu_);
  if (auto it = active_connection_handles_.find(key); it != active_connection_handles_.end()) {
    return it->second;
  }
  return nullptr;
}

size_t StreamTracker::numActiveConnectionHandles() const {
  Thread::LockGuard lock(mu_);
  return active_connection_handles_.size();
}

std::unique_ptr<StreamHandle> StreamTracker::onStreamBegin(stream_id_t stream_id, Network::Connection& connection, StreamCallbacksWeakPtr source_callbacks) {
  auto intf = std::make_shared<StreamInterface>(stream_id, connection, source_callbacks);
  Thread::ReleasableLockGuard lock(mu_);
  ENVOY_LOG(debug, "tracking new ssh stream: id={}", stream_id);
  ASSERT(!active_connection_handles_.contains(stream_id));
  active_connection_handles_.insert({stream_id, intf});
  for (auto& filter : filters_) {
    filter->onStreamBegin(*intf);
  }
  lock.release();
  return std::make_unique<StreamHandle>(stream_id, [this, stream_id] {
    onStreamEnd(stream_id);
  });
}

void StreamTracker::onStreamEnd(stream_id_t stream_id) {
  Thread::LockGuard lock(mu_);
  // onStreamEnd is a no-op if called twice (e.g. called directly, then indirectly from the handle)
  if (auto node = active_connection_handles_.extract(stream_id); !node.empty()) {
    ENVOY_LOG(debug, "tracked ssh stream ended: id={}", stream_id);
    for (auto& filter : filters_) {
      filter->onStreamEnd(*node.mapped());
    }
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
