#include "source/extensions/filters/network/ssh/shared.h"
#include "source/extensions/filters/network/ssh/tunnel_address.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
#include "source/common/config/utility.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SINGLETON_MANAGER_REGISTRATION(ssh_active_stream_tracker); // NOLINT

ActiveStreamInterface::ActiveStreamInterface(stream_id_t stream_id, Network::Connection& connection, std::weak_ptr<ActiveStreamCallbacks> source_callbacks)
    : stream_id_(stream_id),
      callbacks_(source_callbacks),
      source_dispatcher_(connection.dispatcher()) {}

std::shared_ptr<ActiveStreamTracker> ActiveStreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context,
                                                                      const pomerium::extensions::ssh::ActiveStreamTrackerConfig& config) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return context.singletonManager().getTyped<ActiveStreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_active_stream_tracker), [&] { // NOLINT
      std::vector<ActiveStreamTrackerFilterPtr> filters;
      for (const auto& filter_config : config.filters()) {
        auto& factory = Config::Utility::getAndCheckFactory<ActiveStreamTrackerFilterFactory>(filter_config);
        ProtobufTypes::MessagePtr message = factory.createEmptyConfigProto();
        THROW_IF_NOT_OK(Envoy::Config::Utility::translateOpaqueConfig(
          filter_config.typed_config(), context.messageValidationVisitor(), *message));
        filters.push_back(factory.createActiveStreamTrackerFilter(*message, context));
      }
      return std::shared_ptr<ActiveStreamTracker>(new ActiveStreamTracker(std::move(filters)));
    });
}

std::shared_ptr<ActiveStreamTracker> ActiveStreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return context.singletonManager().getTyped<ActiveStreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_active_stream_tracker)); // NOLINT
}

ActiveStreamInterfaceSharedPtr ActiveStreamTracker::find(const Envoy::Network::Address::Instance& addr) const {
  Thread::LockGuard lock(mu_);
  return active_stream_handles_.at(dynamic_cast<const Envoy::Network::Address::InternalStreamAddressImpl&>(addr).streamId());
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
