#include "source/extensions/filters/network/ssh/passthrough_state.h"

namespace Envoy::Network {

void InternalStreamPassthroughState::initialize(std::unique_ptr<envoy::config::core::v3::Metadata> metadata,
                                                const StreamInfo::FilterState::Objects& filter_state_objects) {
  init_mu_.Lock();
  ASSERT(state_ == State::Created);
  PassthroughStateImpl::initialize(std::move(metadata), filter_state_objects);
  ASSERT(state_ == State::Initialized);
  if (init_callback_ == nullptr) {
    init_mu_.Unlock();
    return;
  }
  notifyLocked();
}

void InternalStreamPassthroughState::setOnInitializedCallback(absl::AnyInvocable<void()> callback) {
  init_mu_.Lock();
  ASSERT(init_callback_ == nullptr && state_ < State::Done);
  if (state_ == State::Created) {
    init_callback_ = std::move(callback);
    init_mu_.Unlock();
    return;
  }
  notifyLocked();
}

void InternalStreamPassthroughState::notifyLocked() {
  absl::AnyInvocable<void()> cb;
  std::swap(cb, init_callback_);
  init_mu_.Unlock();
  cb();
}

} // namespace Envoy::Network