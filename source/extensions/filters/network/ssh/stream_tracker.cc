#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/channel.h"

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
  thread_local_stream_table_.set([](Event::Dispatcher&) {
    return std::make_shared<ThreadLocalStreamTable>();
  });
}

void StreamTracker::tryLock(stream_id_t key, absl::AnyInvocable<void(Envoy::OptRef<StreamContext>)> cb) {
  ASSERT(thread_local_stream_table_.get().has_value());
  auto& table = thread_local_stream_table_->get();
  if (auto&& it = table.find(key); it != table.end()) {
    basic_visit(
      it->second,
      [&](Event::Dispatcher* d) {
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
