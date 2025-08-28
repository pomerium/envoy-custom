#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/passthrough_state.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/config/utility.h"
#include "source/common/stream_info/filter_state_impl.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SINGLETON_MANAGER_REGISTRATION(ssh_connection_tracker); // NOLINT

StreamInterface::StreamInterface(stream_id_t stream_id, Network::Connection& connection, StreamCallbacks& stream_callbacks, ChannelEventCallbacks& event_callbacks)
    : stream_id_(stream_id),
      stream_callbacks_(stream_callbacks),
      event_callbacks_(event_callbacks),
      source_dispatcher_(connection.dispatcher()) {}

absl::Status StreamInterface::requestOpenDownstreamChannel(Network::IoHandlePtr io_handle) {
  ENVOY_LOG(debug, "requesting new downstream channel");
  auto passthroughState = Network::InternalStreamPassthroughState::fromIoHandle(*io_handle);
  auto start = absl::Now();
  passthroughState->notifyOnStateChange(
    Network::InternalStreamPassthroughState::Initialized,
    source_dispatcher_,
    [this, start, io_handle = std::move(io_handle)] mutable {
      auto diff = absl::Now() - start;
      ENVOY_LOG(debug, "waited {} for passthrough state initialization", absl::FormatDuration(diff));
      auto c = std::make_unique<InternalDownstreamChannel>(*this, std::move(io_handle), source_dispatcher_, "forwarded-tcpip");
      auto stat = stream_callbacks_.startChannel(std::move(c), std::nullopt);
      if (!stat.ok()) {
        ENVOY_LOG(error, "failed to start channel: {}", statusToString(stat.status()));
        io_handle->close();
      }
    });
  return absl::OkStatus();
}

StreamTrackerSharedPtr StreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context,
                                                  const pomerium::extensions::ssh::StreamTrackerConfig& config) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  auto tracker = fromContext(context);
  tracker->initialize(context, config);
  return tracker;
}

StreamTrackerSharedPtr StreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return context.singletonManager().getTyped<StreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_connection_tracker), [&] { // NOLINT
      return std::shared_ptr<StreamTracker>(new StreamTracker);
    });
}

bool StreamTracker::tryLock(stream_id_t key, std::function<void(StreamInterface&)> cb) {
  Thread::LockGuard lock(mu_);
  if (auto it = active_connection_handles_.find(key); it != active_connection_handles_.end()) {
    cb(*it->second);
    return true;
  }
  return false;
}

size_t StreamTracker::numActiveConnectionHandles() {
  Thread::LockGuard lock(mu_);
  return active_connection_handles_.size();
}

std::unique_ptr<StreamHandle> StreamTracker::onStreamBegin(stream_id_t stream_id, Network::Connection& connection,
                                                           StreamCallbacks& stream_callbacks, ChannelEventCallbacks& event_callbacks) {
  Thread::ReleasableLockGuard lock(mu_);
  auto intf = std::make_unique<StreamInterface>(stream_id, connection, stream_callbacks, event_callbacks);
  ENVOY_LOG(debug, "tracking new ssh stream: id={}", stream_id);
  ASSERT(!active_connection_handles_.contains(stream_id));
  for (auto& filter : filters_) {
    filter->onStreamBegin(*intf);
  }
  active_connection_handles_.insert({stream_id, std::move(intf)});
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

void StreamTracker::initialize(Server::Configuration::ServerFactoryContext& context, const StreamTrackerConfig& config) {
  Thread::LockGuard lock(mu_);
  std::vector<StreamTrackerFilterPtr> filters;

  for (const auto& filter_config : config.filters()) {
    auto& factory = Config::Utility::getAndCheckFactory<StreamTrackerFilterFactory>(filter_config);
    ProtobufTypes::MessagePtr message = factory.createEmptyConfigProto();
    THROW_IF_NOT_OK(Envoy::Config::Utility::translateOpaqueConfig(
      filter_config.typed_config(), context.messageValidationVisitor(), *message));
    filters.push_back(factory.createStreamTrackerFilter(*message, context));
  }

  std::swap(filters, filters_);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
