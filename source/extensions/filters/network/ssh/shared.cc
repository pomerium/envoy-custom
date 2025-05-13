#include "source/extensions/filters/network/ssh/shared.h"
#include "source/common/common/lock_guard.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ActiveSession::ActiveSession(stream_id_t stream_id, std::weak_ptr<SourceCallbacks> source_callbacks)
    : stream_id_(stream_id),
      source_callbacks_(source_callbacks) {}

void ActiveSession::disconnectAllMirrors() {
  Thread::LockGuard lock(mirrors_mu_);
  for (auto&& it = mirrors_.begin(); it != mirrors_.end();) {
    if (!it->expired()) {
      it->lock()->onStreamEnd("session ended");
      it++;
    } else {
      it = mirrors_.erase(it);
    }
  }
}

std::weak_ptr<SourceInterface> ActiveSession::attach(std::weak_ptr<MirrorCallbacks> mc) {
  Thread::LockGuard lock(mirrors_mu_);
  if (mirrors_.contains(mc)) {
    PANIC("bug: ActiveSession::attach() called twice with the same object");
  }
  mirrors_.insert(mc);
  if (auto s = source_callbacks_.lock(); s) {
    s->onMirrorAdded(mc);
  }
  return source_callbacks_;
}
void ActiveSession::detach(std::shared_ptr<MirrorCallbacks> mc) {
  Thread::LockGuard lock(mirrors_mu_);
  mirrors_.erase(mc);
}

ThreadLocalData::ThreadLocalData(ActiveSessionsMap shared_sessions)
    : active_sessions_(std::move(shared_sessions)) {}

void ThreadLocalData::beginSession(stream_id_t session_id, std::weak_ptr<SourceCallbacks> source_callbacks) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "ThreadLocalData::beginSession [id={}]", session_id);
  (*active_sessions_)[session_id] = std::make_shared<ActiveSession>(session_id, source_callbacks);

  if (awaiters_.contains(session_id)) {
    for (auto&& awaiter : awaiters_[session_id]) {
      if (auto a = awaiter.lock(); a) {
        a->setSourceInterface(source_callbacks);
      }
    }
    awaiters_.erase(session_id);
  }
}

absl::Status ThreadLocalData::shutdownSession(stream_id_t session_id) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "ThreadLocalData::shutdownSession [id={}]", session_id);
  if (auto it = active_sessions_->find(session_id); it != active_sessions_->end()) {
    it->second->disconnectAllMirrors();
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError("session not found");
}

void ThreadLocalData::endSession(stream_id_t session_id) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "ThreadLocalData::endSession [id={}]", session_id);
  active_sessions_->erase(session_id);
}

absl::StatusOr<std::weak_ptr<SourceInterface>>
ThreadLocalData::attachToSession(stream_id_t session_id, std::weak_ptr<MirrorCallbacks> cb) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "ThreadLocalData::attachToSession [id={}]", session_id);
  if (auto it = active_sessions_->find(session_id); it != active_sessions_->end()) {
    ENVOY_LOG(debug, "session is still active: {}", it->first);
    return it->second->attach(cb);
  }
  ENVOY_LOG(debug, "session not found: {}", session_id);
  return absl::NotFoundError("session not found");
}

absl::Status ThreadLocalData::detachFromSession(stream_id_t session_id, std::shared_ptr<MirrorCallbacks> cb) {
  Thread::LockGuard lock(sessions_mu_);
  ENVOY_LOG(debug, "ThreadLocalData::detachFromSession [id={}]", session_id);
  if (auto it = active_sessions_->find(session_id); it != active_sessions_->end()) {
    ENVOY_LOG(debug, "session is still active: {}", it->first);
    it->second->detach(cb);
    return absl::OkStatus();
  } else {
    ENVOY_LOG(debug, "session not found: {}", session_id);
    return absl::InternalError("session not found");
  }
}

void ThreadLocalData::awaitSession(stream_id_t session_id, std::shared_ptr<SourceInterfaceCallbacks> callbacks) {
  Thread::LockGuard lock(sessions_mu_);
  awaiters_[session_id].insert(std::weak_ptr(callbacks));
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec