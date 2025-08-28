#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/extensions/io_socket/user_space/io_handle_impl.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network {

class InternalStreamPassthroughState : public Envoy::Extensions::IoSocket::UserSpace::PassthroughStateImpl {
public:
  void initialize(std::unique_ptr<envoy::config::core::v3::Metadata> metadata,
                  const StreamInfo::FilterState::Objects& filter_state_objects) override;

  void mergeInto(envoy::config::core::v3::Metadata& metadata,
                 StreamInfo::FilterState& filter_state) override;

  void notifyOnStateChange(State state, Event::Dispatcher& dispatcher, Event::PostCb callback);

  using enum PassthroughStateImpl::State;

  static std::shared_ptr<InternalStreamPassthroughState> fromIoHandle(Network::IoHandle& io_handle) {
    return std::dynamic_pointer_cast<Network::InternalStreamPassthroughState>(
      dynamic_cast<Extensions::IoSocket::UserSpace::IoHandleImpl&>(io_handle).passthroughState());
  }

private:
  void notifyLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
  struct Waiter {
    State state;
    Event::Dispatcher& dispatcher;
    Event::PostCb callback;
  };
  Thread::MutexBasicLockable mu_;
  std::list<Waiter> waiters_;
};

} // namespace Envoy::Network
