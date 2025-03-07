#pragma once

#include "envoy/event/dispatcher.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"

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
  ActiveSession(uint64_t session_id, std::shared_ptr<SourceCallbacks> source_callbacks);

  void disconnectAllMirrors();
  std::shared_ptr<SourceInterface> attach(std::shared_ptr<MirrorCallbacks> mc);
  void detach(std::shared_ptr<MirrorCallbacks> mc);

  uint64_t sessionId() { return session_id_; }

private:
  uint64_t session_id_;
  Thread::ThreadId source_thread_;
  std::shared_ptr<SourceCallbacks> source_callbacks_;

  Thread::MutexBasicLockable mirrors_mu_;
  std::vector<std::shared_ptr<MirrorCallbacks>> mirrors_;
};

class MirrorCallbacksDispatcher : public MirrorCallbacks,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  MirrorCallbacksDispatcher(std::shared_ptr<MirrorCallbacks> callbacks, Dispatcher* dispatcher);

  void onMsg(const wire::Message& msg) override;
  void onEnd() override;

private:
  std::shared_ptr<MirrorCallbacks> base_;
  Dispatcher* mirror_dispatcher_;
};

class SourceCallbacksDispatcher : public SourceCallbacks,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  SourceCallbacksDispatcher(std::shared_ptr<SourceCallbacks> callbacks, Dispatcher* dispatcher);

  void inject(const wire::ChannelDataMsg& msg) override;

  void onMirrorAdded(std::shared_ptr<MirrorCallbacks> mc) override;
  void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) override;

private:
  std::shared_ptr<SourceCallbacks> base_;
  Dispatcher* source_dispatcher_;
};

class SharedThreadLocalData : public ThreadLocal::ThreadLocalObject,
                              public Logger::Loggable<Logger::Id::filter> {
public:
  using ActiveSessionsMap = std::shared_ptr<absl::node_hash_map<uint64_t, std::shared_ptr<ActiveSession>>>;
  SharedThreadLocalData(ActiveSessionsMap shared_sessions);
  void beginSession(uint64_t session_id,
                    std::shared_ptr<SourceCallbacks> source_callbacks,
                    Dispatcher* dispatcher);
  void shutdownSession(uint64_t session_id);
  void endSession(uint64_t session_id);

  std::shared_ptr<SourceInterface>
  attachToSession(uint64_t session_id, std::shared_ptr<MirrorCallbacks> cb, Dispatcher* local_dispatcher);
  void detachFromSession(uint64_t session_id, std::shared_ptr<MirrorCallbacks> cb);

private:
  Thread::MutexBasicLockable sessions_mu_;
  ActiveSessionsMap ABSL_GUARDED_BY(sessions_mu_) active_sessions_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
