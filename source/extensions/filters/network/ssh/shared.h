#pragma once

#include <memory>

#pragma clang unsafe_buffer_usage begin
#include "source/common/common/thread.h"
#include "envoy/thread_local/thread_local_object.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class MirrorCallbacks {
public:
  virtual ~MirrorCallbacks() = default;
  virtual void sendMsg(wire::Message&& msg) PURE;
  virtual void onSourceResized(int width, int height) PURE;
  virtual void onStreamEnd(const std::string& msg) PURE;
};

class SourceInterface {
public:
  virtual ~SourceInterface() = default;
  virtual void inject(wire::ChannelDataMsg&& msg) PURE;
  virtual void resize(const wire::WindowDimensionChangeChannelRequestMsg& msg) PURE;
};

class SourceCallbacks : public SourceInterface {
public:
  virtual ~SourceCallbacks() = default;
  virtual void onMirrorAdded(std::weak_ptr<MirrorCallbacks> mc) PURE;
  virtual void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) PURE;
};

class SourceInterfaceCallbacks {
public:
  virtual ~SourceInterfaceCallbacks() = default;
  virtual void setSourceInterface(std::weak_ptr<SourceInterface>) PURE;
};

class ActiveSession {
public:
  ActiveSession(stream_id_t stream_id, std::weak_ptr<SourceCallbacks> source_callbacks);

  void disconnectAllMirrors();
  std::weak_ptr<SourceInterface> attach(std::weak_ptr<MirrorCallbacks> mc);
  void detach(std::shared_ptr<MirrorCallbacks> mc);

  stream_id_t sessionId() { return stream_id_; }

private:
  stream_id_t stream_id_;
  Thread::ThreadId source_thread_;
  std::weak_ptr<SourceCallbacks> source_callbacks_;

  Thread::MutexBasicLockable mirrors_mu_;
  std::set<std::weak_ptr<MirrorCallbacks>, std::owner_less<>> mirrors_;
};

class ThreadLocalData : public ThreadLocal::ThreadLocalObject,
                        public Logger::Loggable<Logger::Id::filter> {
public:
  using ActiveSessionsMap = std::shared_ptr<absl::node_hash_map<stream_id_t, std::shared_ptr<ActiveSession>>>;
  ThreadLocalData(ActiveSessionsMap shared_sessions);
  void beginSession(stream_id_t session_id, std::weak_ptr<SourceCallbacks> source_callbacks);
  void awaitSession(stream_id_t session_id, std::shared_ptr<SourceInterfaceCallbacks> callbacks);
  absl::Status shutdownSession(stream_id_t session_id);
  void endSession(stream_id_t session_id);

  absl::StatusOr<std::weak_ptr<SourceInterface>>
  attachToSession(stream_id_t session_id, std::weak_ptr<MirrorCallbacks> cb);
  absl::Status detachFromSession(stream_id_t session_id, std::shared_ptr<MirrorCallbacks> cb);

private:
  Thread::MutexBasicLockable sessions_mu_;
  ActiveSessionsMap ABSL_GUARDED_BY(sessions_mu_) active_sessions_;
  std::unordered_map<stream_id_t, std::set<std::weak_ptr<SourceInterfaceCallbacks>, std::owner_less<>>> ABSL_GUARDED_BY(sessions_mu_) awaiters_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
