#include "source/extensions/filters/network/ssh/shared.h"
#include "source/extensions/filters/network/ssh/tunnel_address.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SINGLETON_MANAGER_REGISTRATION(ssh_active_stream_tracker); // NOLINT

ActiveStreamInterface::ActiveStreamInterface(stream_id_t stream_id, ::Envoy::Event::Dispatcher& source_dispatcher, std::weak_ptr<ActiveStreamCallbacks> source_callbacks)
    : stream_id_(stream_id),
      callbacks_(source_callbacks),
      source_dispatcher_(source_dispatcher) {}

// void ThreadLocalData::onStreamBegin(stream_id_t stream_id, ::Envoy::Event::Dispatcher& source_dispatcher, std::weak_ptr<ActiveStreamCallbacks> callbacks) {
//   ENVOY_LOG(info, "ThreadLocalData::onStreamBegin [id={}]", stream_id);
//   stream_tracker_->insert(stream_id, std::make_shared<ActiveStreamHandle>(stream_id, source_dispatcher, callbacks));
// }

// absl::Status ThreadLocalData::shutdownStream(stream_id_t stream_id) {
//   ENVOY_LOG(info, "ThreadLocalData::shutdownStream [id={}]", stream_id);
//   if (auto ptr = stream_tracker_->at(stream_id); ptr != nullptr) {
//     return absl::OkStatus();
//   }
//   return absl::InvalidArgumentError("stream not found");
// }

// void ThreadLocalData::onStreamEnd(stream_id_t stream_id) {
//   ENVOY_LOG(info, "ThreadLocalData::onStreamEnd [id={}]", stream_id);
//   stream_tracker_->erase(stream_id);
// }

// absl::Status ThreadLocalData::requestOpenDownstreamChannel(Network::Address::InstanceConstSharedPtr addr, Network::IoHandlePtr io_handle) {
//   auto addrImpl = dynamic_cast<const Network::Address::InternalStreamAddressImpl*>(addr.get());
//   auto ptr = stream_tracker_->at(addrImpl->streamId());
//   if (ptr != nullptr) {
//     return ptr->requestOpenDownstreamChannel(std::move(io_handle));
//   }
//   return absl::NotFoundError("stream not found");
// }
std::shared_ptr<ActiveStreamTracker> ActiveStreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context) {
  return context.singletonManager().getTyped<ActiveStreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_active_stream_tracker), [] { // NOLINT
      return std::make_shared<ActiveStreamTracker>();
    });
}

absl::Status ActiveStreamTracker::requestOpenDownstreamChannel(Network::Address::InstanceConstSharedPtr addr, Network::IoHandlePtr io_handle) {
  auto addrImpl = dynamic_cast<const Network::Address::InternalStreamAddressImpl*>(addr.get());
  auto ptr = at(addrImpl->streamId());
  if (ptr != nullptr) {
    return ptr->requestOpenDownstreamChannel(std::move(io_handle));
  }
  return absl::NotFoundError("stream not found");
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
