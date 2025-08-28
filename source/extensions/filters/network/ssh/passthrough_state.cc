#include "source/extensions/filters/network/ssh/passthrough_state.h"

namespace Envoy::Network {

void InternalStreamPassthroughState::initialize(std::unique_ptr<envoy::config::core::v3::Metadata> metadata,
                                                const StreamInfo::FilterState::Objects& filter_state_objects) {
  Thread::LockGuard lock(mu_);
  ASSERT(state_ == State::Created);
  PassthroughStateImpl::initialize(std::move(metadata), filter_state_objects);
  ASSERT(state_ == State::Initialized);
  notifyLocked();
}

void InternalStreamPassthroughState::mergeInto(envoy::config::core::v3::Metadata& metadata,
                                               StreamInfo::FilterState& filter_state) {
  Thread::LockGuard lock(mu_);
  ASSERT(state_ == State::Initialized);
  PassthroughStateImpl::mergeInto(metadata, filter_state);
  ASSERT(state_ == State::Done);
  notifyLocked();
}

void InternalStreamPassthroughState::notifyOnStateChange(State state, Event::Dispatcher& dispatcher, Event::PostCb callback) {
  Thread::ReleasableLockGuard lock(mu_);
  if (static_cast<int>(state_) >= static_cast<int>(state)) {
    lock.release();
    dispatcher.post(std::move(callback));
    return;
  }
  waiters_.push_back({state, dispatcher, std::move(callback)});
}

void InternalStreamPassthroughState::notifyLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
  for (auto it = waiters_.begin(); it != waiters_.end();) {
    if (static_cast<int>(state_) >= static_cast<int>(it->state)) {
      it->dispatcher.post(std::move(it->callback));
      it = waiters_.erase(it);
    } else {
      it++;
    }
  }
}

} // namespace Envoy::Network