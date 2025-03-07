#include "source/extensions/filters/network/ssh/shared.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ActiveSession::ActiveSession(uint64_t session_id,
                             std::shared_ptr<SourceCallbacks> source_callbacks)
    : session_id_(session_id),
      source_callbacks_(source_callbacks) {}

void ActiveSession::disconnectAllMirrors() {
  Thread::LockGuard lock(mirrors_mu_);
  for (const auto& mirror : mirrors_) {
    mirror->onEnd();
  }
}

std::shared_ptr<SourceInterface> ActiveSession::attach(std::shared_ptr<MirrorCallbacks> mc) {
  Thread::LockGuard lock(mirrors_mu_);
  mirrors_.push_back(mc);
  source_callbacks_->onMirrorAdded(mc);
  return source_callbacks_;
}
void ActiveSession::detach(std::shared_ptr<MirrorCallbacks> mc) {
  Thread::LockGuard lock(mirrors_mu_);
  mirrors_.erase(std::remove(mirrors_.begin(), mirrors_.end(), mc), mirrors_.end());
  source_callbacks_->onMirrorRemoved(mc);
}

MirrorCallbacksDispatcher::MirrorCallbacksDispatcher(std::shared_ptr<MirrorCallbacks> callbacks, Dispatcher* dispatcher)
    : base_(callbacks), mirror_dispatcher_(dispatcher) {}
void MirrorCallbacksDispatcher::onMsg(const wire::Message& msg) {
  mirror_dispatcher_->post([base = base_, &msg = msg]() {
    ENVOY_LOG(debug, "posted callback: onMsg");
    base->onMsg(msg);
  });
};

void MirrorCallbacksDispatcher::onEnd() {
  mirror_dispatcher_->post([base = base_]() {
    ENVOY_LOG(debug, "posted callback: onEnd");
    base->onEnd();
  });
};

SourceCallbacksDispatcher::SourceCallbacksDispatcher(std::shared_ptr<SourceCallbacks> callbacks, Dispatcher* dispatcher)
    : base_(callbacks), source_dispatcher_(dispatcher) {}

void SourceCallbacksDispatcher::inject(const wire::ChannelDataMsg& msg) {
  source_dispatcher_->post([base = base_, msg = msg]() {
    ENVOY_LOG(debug, "posted callback: onInject");
    base->inject(msg);
  });
}
void SourceCallbacksDispatcher::onMirrorAdded(std::shared_ptr<MirrorCallbacks> mc) {
  source_dispatcher_->post([base = base_, mc = std::move(mc)]() {
    ENVOY_LOG(debug, "posted callback: onMirrorAdded");
    base->onMirrorAdded(mc);
  });
};

void SourceCallbacksDispatcher::onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) {
  source_dispatcher_->post([base = base_, mc = mc]() {
    ENVOY_LOG(debug, "posted callback: onMirrorRemoved");
    base->onMirrorRemoved(mc);
  });
};

SharedThreadLocalData::SharedThreadLocalData(ActiveSessionsMap shared_sessions)
    : active_sessions_(shared_sessions) {}

void SharedThreadLocalData::beginSession(uint64_t session_id,
                                         std::shared_ptr<SourceCallbacks> source_callbacks,
                                         Dispatcher* dispatcher) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "SharedThreadLocalData::beginSession [id={}]", session_id);
  (*active_sessions_)[session_id] = std::make_shared<ActiveSession>(
    session_id, std::make_shared<SourceCallbacksDispatcher>(source_callbacks, dispatcher));
}

void SharedThreadLocalData::shutdownSession(uint64_t session_id) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "SharedThreadLocalData::shutdownSession [id={}]", session_id);
  active_sessions_->at(session_id)->disconnectAllMirrors();
}

void SharedThreadLocalData::endSession(uint64_t session_id) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "SharedThreadLocalData::endSession [id={}]", session_id);
  active_sessions_->erase(session_id);
}

std::shared_ptr<SourceInterface>
SharedThreadLocalData::attachToSession(uint64_t session_id, std::shared_ptr<MirrorCallbacks> cb, Dispatcher* local_dispatcher) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "SharedThreadLocalData::attachToSession [id={}]", session_id);
  return active_sessions_->at(session_id)->attach(std::make_shared<MirrorCallbacksDispatcher>(cb, local_dispatcher));
}

void SharedThreadLocalData::detachFromSession(uint64_t session_id, std::shared_ptr<MirrorCallbacks> cb) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "SharedThreadLocalData::detachFromSession [id={}]", session_id);
  return active_sessions_->at(session_id)->detach(cb);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec