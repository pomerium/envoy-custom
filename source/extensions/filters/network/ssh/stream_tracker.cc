#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/channel.h"
#include "absl/synchronization/blocking_counter.h"
#include "source/common/event/deferred_task.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SINGLETON_MANAGER_REGISTRATION(ssh_stream_tracker); // NOLINT

StreamTrackerSharedPtr StreamTracker::fromContext(Server::Configuration::ServerFactoryContext& context) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return context.singletonManager().getTyped<StreamTracker>(
    SINGLETON_MANAGER_REGISTERED_NAME(ssh_stream_tracker), [&] { // NOLINT
      return std::make_shared<StreamTracker>(context);
    });
}

StreamTracker::StreamTracker(Server::Configuration::ServerFactoryContext& context)
    : thread_local_stream_table_(context.threadLocal()),
      main_thread_dispatcher_(context.mainThreadDispatcher()),
      scope_(context.scope()),
      stat_names_(scope_.symbolTable()),
      stats_(stat_names_, scope_, stat_names_.ssh_) {
  shutdown_cb_ = context.lifecycleNotifier().registerCallback(
    Envoy::Server::ServerLifecycleNotifier::Stage::ShutdownExit,
    [this](Envoy::Event::PostCb shutdown_guard) {
      ASSERT(main_thread_dispatcher_.isThreadSafe());
      if (shutdown_completed_) {
        return;
      }
      inflight_shutdown_guards_.push_back(std::move(shutdown_guard));
      if (shutdown_started_) {
        // If shutdown is in-progress but not completed, we just need to keep shutdown_guard alive
        // until the in-flight shutdown is complete, otherwise it will exit early.
        return;
      }
      ENVOY_LOG(info, "ssh: starting graceful shutdown (server lifecycle)");
      startGracefulShutdown(std::chrono::milliseconds{0}, [this, start = absl::Now()] {
        ASSERT(main_thread_dispatcher_.isThreadSafe());
        ENVOY_LOG(info, "ssh: shutdown completed after {}", absl::FormatDuration(absl::Now() - start));
        inflight_shutdown_guards_.clear();
      });
    });
  drain_mgr_cb_ = context.drainManager().addOnDrainCloseCb(
    Network::DrainDirection::InboundOnly,
    [this](std::chrono::milliseconds delay) {
      ASSERT(main_thread_dispatcher_.isThreadSafe());
      if (shutdown_started_) {
        return absl::OkStatus();
      }
      ENVOY_LOG(info, "ssh: starting graceful shutdown (drain)");
      startGracefulShutdown(delay, [this, start = absl::Now()] {
        ASSERT(main_thread_dispatcher_.isThreadSafe());
        ENVOY_LOG(info, "ssh: shutdown completed after {}", absl::FormatDuration(absl::Now() - start));
      });
      return absl::OkStatus();
    });
  thread_local_stream_table_.set([](Envoy::Event::Dispatcher&) {
    return std::make_shared<ThreadLocalStreamTable>();
  });
}

namespace {
class DeferredDeleteHandle : public Envoy::Event::DeferredDeletable {
public:
  DeferredDeleteHandle(Envoy::Common::CallbackHandlePtr&& handle)
      : handle_(std::move(handle)) {}

private:
  Envoy::Common::CallbackHandlePtr handle_;
};
} // namespace

void StreamTracker::startGracefulShutdown(std::chrono::milliseconds delay, std::function<void()> complete_cb) {
  ASSERT(main_thread_dispatcher_.isThreadSafe());
  ASSERT(!shutdown_started_);
  shutdown_started_ = true;

  std::shared_ptr<void> wg = std::make_shared<Cleanup>([this, complete_cb] {
    ENVOY_LOG(info, "ssh: all streams shutdown");
    shutdown_completed_ = true;
    main_thread_dispatcher_.post(std::move(complete_cb));
  });

  thread_local_stream_table_.runOnAllThreads(
    [this, delay, wg](Envoy::OptRef<ThreadLocalStreamTable> obj) {
      for (auto& [stream_id, ctx] : obj->get()) {
        basic_visit(
          ctx,
          [](Envoy::Event::Dispatcher*) {},
          [this, delay, wg](StreamContext& ctx) {
            auto id = ctx.streamId();
            auto& dispatcher = ctx.connection().dispatcher();

            auto handle = ctx.streamCallbacks().onServerDraining(
              delay, dispatcher,
              [this, wg, id, dispatcher = &dispatcher] {
                ENVOY_LOG(info, "ssh: stream {}: shutdown complete", id);
                drain_cb_mu_.Lock();
                auto deferredDelete = channel_id_mgr_drain_cbs_.extract(id);
                drain_cb_mu_.Unlock();
                // It is not safe to delete the callback handle from within the callback, as it can
                // cause an internal deadlock in the ThreadSafeCallbackManager. Normally we can just
                // ignore these handles, but they need to be explicitly deleted because the closure
                // objects hold references to wg that must be released for complete_cb to run.
                dispatcher->deferredDelete(std::make_unique<DeferredDeleteHandle>(std::move(deferredDelete.mapped())));
              });

            // Note: order is important here when acquiring this lock.
            drain_cb_mu_.Lock();
            channel_id_mgr_drain_cbs_[id] = std::move(handle);
            drain_cb_mu_.Unlock();
          });
      }
    },
    [wg] {});
}

void StreamTracker::tryLock(stream_id_t key, absl::AnyInvocable<void(Envoy::OptRef<StreamContext>)> cb) {
  ASSERT(thread_local_stream_table_.get().has_value());
  auto& table = thread_local_stream_table_->get();
  if (auto&& it = table.find(key); it != table.end()) {
    basic_visit(
      it->second,
      [&](Envoy::Event::Dispatcher* d) {
        d->post([this, key, cb = std::move(cb)] mutable {
          tryLock(key, std::move(cb));
        });
      },
      [&](StreamContext& ctx) {
        // Note: the StreamContext cannot be invalidated during the callback, because
        // this runs in the connection's thread.
        cb(ctx);
      });
  } else {
    cb({});
  }
}

std::unique_ptr<StreamHandle> StreamTracker::onStreamBegin(stream_id_t stream_id,
                                                           Network::Connection& connection,
                                                           StreamCallbacks& stream_callbacks,
                                                           ChannelEventCallbacks& event_callbacks,
                                                           const std::function<void()>& on_sync_complete) {
  ASSERT(thread_local_stream_table_.get().has_value());
  ASSERT(connection.dispatcher().isThreadSafe());

  ENVOY_LOG(debug, "tracking new ssh stream: id={}", stream_id);
  stats_.total_streams_.inc();
  stats_.active_streams_.inc();

  // Note: stream IDs are random, not sequential
  thread_local_stream_table_->get()
    .try_emplace(stream_id, StreamContext(stream_id, connection, stream_callbacks, event_callbacks));

  main_thread_dispatcher_.post([self = weak_from_this(), stream_id, dispatcher = &connection.dispatcher(), on_sync_complete] {
    auto st = self.lock();
    if (st == nullptr || st->thread_local_stream_table_.isShutdown()) {
      return;
    }
    const auto update = [stream_id, dispatcher](Envoy::OptRef<ThreadLocalStreamTable> obj) {
      obj->get().try_emplace(stream_id, dispatcher);
    };
    if (on_sync_complete == nullptr) {
      st->thread_local_stream_table_.runOnAllThreads(update);
    } else {
      st->thread_local_stream_table_.runOnAllThreads(update, on_sync_complete);
    }
  });
  return absl::WrapUnique(new StreamHandle(stream_id, weak_from_this()));
}

void StreamTracker::onStreamEnd(stream_id_t stream_id) {
  ASSERT(thread_local_stream_table_.get().has_value());
  auto n = thread_local_stream_table_->get().erase(stream_id);
  ASSERT(n == 1);
  ENVOY_LOG(debug, "tracked ssh stream ended: id={}", stream_id);
  stats_.active_streams_.dec();
  main_thread_dispatcher_.post([self = weak_from_this(), stream_id] {
    auto st = self.lock();
    if (st == nullptr || st->thread_local_stream_table_.isShutdown()) {
      return;
    }
    st->thread_local_stream_table_.runOnAllThreads(
      [stream_id](Envoy::OptRef<ThreadLocalStreamTable> obj) {
        auto node = obj->get().extract(stream_id);
        ASSERT(node.empty() || std::holds_alternative<::Envoy::Event::Dispatcher*>(node.mapped()));
      });
  });
}

StreamHandle::StreamHandle(stream_id_t id, std::weak_ptr<StreamTracker> parent)
    : id_(id),
      parent_(std::move(parent)) {
}

StreamHandle::~StreamHandle() {
  if (auto st = parent_.lock(); st != nullptr) {
    st->onStreamEnd(id_);
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
