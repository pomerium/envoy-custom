#pragma once

#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "envoy/event/dispatcher.h"
#include "wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using ::Envoy::Event::Dispatcher;

class MirrorCallbacks {
public:
  virtual ~MirrorCallbacks() = default;
  virtual void onMsg(const wire::Message& msg) PURE;
  virtual void onEnd() PURE;
};

class SourceInterface {
public:
  virtual ~SourceInterface() = default;
  virtual void inject(const wire::ChannelDataMsg& msg) PURE;
};

class SourceCallbacks : public SourceInterface {
public:
  virtual ~SourceCallbacks() = default;
  virtual void onMirrorAdded(std::shared_ptr<MirrorCallbacks> mc) PURE;
  virtual void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) PURE;
};

class ActiveSession {
public:
  ActiveSession(uint64_t session_id,
                Thread::ThreadId source_thread,
                std::shared_ptr<SourceCallbacks> source_callbacks)
      : session_id_(session_id),
        source_thread_(source_thread),
        source_callbacks_(source_callbacks) {}

  uint64_t sessionId() {
    return session_id_;
  }

  Thread::ThreadId sourceThread() {
    return source_thread_;
  }

  void disconnectAllMirrors() {
    Thread::LockGuard lock(mirrors_mu_);
    for (const auto& mirror : mirrors_) {
      mirror->onEnd();
    }
  }

  std::shared_ptr<SourceInterface> attach(std::shared_ptr<MirrorCallbacks> mc) {
    Thread::LockGuard lock(mirrors_mu_);
    mirrors_.push_back(mc);
    source_callbacks_->onMirrorAdded(mc);
    return source_callbacks_;
  }

  void detach(std::shared_ptr<MirrorCallbacks> mc) {
    Thread::LockGuard lock(mirrors_mu_);
    mirrors_.erase(std::remove(mirrors_.begin(), mirrors_.end(), mc), mirrors_.end());
    source_callbacks_->onMirrorRemoved(mc);
  }

private:
  uint64_t session_id_;
  Thread::ThreadId source_thread_;
  std::shared_ptr<SourceCallbacks> source_callbacks_;

  Thread::MutexBasicLockable mirrors_mu_;
  std::vector<std::shared_ptr<MirrorCallbacks>> mirrors_;
};

class MirrorCallbacksDispatcher : public MirrorCallbacks, public Logger::Loggable<Logger::Id::filter> {
public:
  MirrorCallbacksDispatcher(std::shared_ptr<MirrorCallbacks> callbacks, Dispatcher* dispatcher)
      : base_(callbacks), mirror_dispatcher_(dispatcher) {}

  void onMsg(const wire::Message& msg) override {
    mirror_dispatcher_->post([base = base_, &msg = msg]() {
      ENVOY_LOG(debug, "posted callback: onMsg");
      base->onMsg(msg);
    });
  };

  void onEnd() override {
    mirror_dispatcher_->post([base = base_]() {
      ENVOY_LOG(debug, "posted callback: onEnd");
      base->onEnd();
    });
  };

private:
  std::shared_ptr<MirrorCallbacks> base_;
  Dispatcher* mirror_dispatcher_;
};

class SourceCallbacksDispatcher : public SourceCallbacks, public Logger::Loggable<Logger::Id::filter> {
public:
  SourceCallbacksDispatcher(std::shared_ptr<SourceCallbacks> callbacks, Dispatcher* dispatcher)
      : base_(callbacks), source_dispatcher_(dispatcher) {}

  void inject(const wire::ChannelDataMsg& msg) override {
    source_dispatcher_->post([base = base_, msg = msg]() {
      ENVOY_LOG(debug, "posted callback: onInject");
      base->inject(msg);
    });
  }

  void onMirrorAdded(std::shared_ptr<MirrorCallbacks> mc) override {
    source_dispatcher_->post([base = base_, mc = std::move(mc)]() {
      ENVOY_LOG(debug, "posted callback: onMirrorAdded");
      base->onMirrorAdded(mc);
    });
  };
  void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) override {
    source_dispatcher_->post([base = base_, mc = mc]() {
      ENVOY_LOG(debug, "posted callback: onMirrorRemoved");
      base->onMirrorRemoved(mc);
    });
  };

private:
  std::shared_ptr<SourceCallbacks> base_;
  Dispatcher* source_dispatcher_;
};

class SharedThreadLocalData : public ThreadLocal::ThreadLocalObject, public Logger::Loggable<Logger::Id::filter> {
public:
  SharedThreadLocalData(std::shared_ptr<absl::node_hash_map<uint64_t, std::shared_ptr<ActiveSession>>> shared_sessions)
      : active_sessions_(shared_sessions) {}
  void beginSession(uint64_t session_id,
                    Thread::ThreadId thread,
                    std::shared_ptr<SourceCallbacks> source_callbacks,
                    Dispatcher* dispatcher) {
    Thread::LockGuard lock(sessions_mu_);
    ENVOY_LOG(debug, "SharedThreadLocalData::beginSession [id={}]", session_id);
    (*active_sessions_)[session_id] = std::make_shared<ActiveSession>(
      session_id, thread, std::make_shared<SourceCallbacksDispatcher>(source_callbacks, dispatcher));
  }
  void shutdownSession(uint64_t session_id) {
    Thread::LockGuard lock(sessions_mu_);
    ENVOY_LOG(debug, "SharedThreadLocalData::shutdownSession [id={}]", session_id);
    active_sessions_->at(session_id)->disconnectAllMirrors();
  }
  void endSession(uint64_t session_id) {
    Thread::LockGuard lock(sessions_mu_);
    ENVOY_LOG(debug, "SharedThreadLocalData::endSession [id={}]", session_id);
    active_sessions_->erase(session_id);
  }

  std::shared_ptr<SourceInterface>
  attachToSession(uint64_t session_id, std::shared_ptr<MirrorCallbacks> cb, Dispatcher* local_dispatcher) {
    Thread::LockGuard lock(sessions_mu_);
    ENVOY_LOG(debug, "SharedThreadLocalData::attachToSession [id={}]", session_id);
    return active_sessions_->at(session_id)->attach(std::make_shared<MirrorCallbacksDispatcher>(cb, local_dispatcher));
  }

  void detachFromSession(uint64_t session_id, std::shared_ptr<MirrorCallbacks> cb) {
    Thread::LockGuard lock(sessions_mu_);
    ENVOY_LOG(debug, "SharedThreadLocalData::detachFromSession [id={}]", session_id);
    return active_sessions_->at(session_id)->detach(cb);
  }

private:
  Thread::MutexBasicLockable sessions_mu_;
  std::shared_ptr<absl::node_hash_map<uint64_t, std::shared_ptr<ActiveSession>>> ABSL_GUARDED_BY(sessions_mu_) active_sessions_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
