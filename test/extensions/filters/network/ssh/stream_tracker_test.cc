#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/stream_tracker.h"

#include "test/test_common/utility.h"
#include "absl/synchronization/blocking_counter.h"
#include "test/test_common/test_common.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/real_threads_test_helper.h"
#include "absl/synchronization/notification.h"
#include "absl/synchronization/barrier.h"
#include "envoy/stats/stats.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class StreamTrackerTest : public testing::Test {
public:
  void SetUp() {
    st = StreamTracker::fromContext(context);
    active_streams_ = context.store_.gauge("ssh.active_streams", Stats::Gauge::ImportMode::Accumulate);
    total_streams_ = context.store_.counter("ssh.total_streams");
  }
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;
  Envoy::OptRef<Stats::Gauge> active_streams_;
  Envoy::OptRef<Stats::Counter> total_streams_;
  StreamTrackerSharedPtr st;
};

TEST_F(StreamTrackerTest, FromContext) {
  auto st = StreamTracker::fromContext(context);
  ASSERT_NE(nullptr, st);

  auto st2 = StreamTracker::fromContext(context);
  ASSERT_NE(nullptr, st);
  ASSERT_EQ(st, st2);
}

class TestStreamCallbacks : public StreamCallbacks, public ChannelEventCallbacks {
public:
  virtual ~TestStreamCallbacks() = default;
  MOCK_METHOD(absl::StatusOr<uint32_t>, startChannel, (std::unique_ptr<Channel>, std::optional<uint32_t>));
  MOCK_METHOD(void, sendChannelEvent, (const pomerium::extensions::ssh::ChannelEvent&));
};

TEST_F(StreamTrackerTest, TryLock) {
  auto testCallbacks1 = std::make_shared<TestStreamCallbacks>();
  auto testCallbacks2 = std::make_shared<TestStreamCallbacks>();

  testing::NiceMock<Network::MockConnection> conn1;
  testing::NiceMock<Network::MockConnection> conn2;

  auto handle1 = st->onStreamBegin(1, conn1, *testCallbacks1, *testCallbacks1);
  ASSERT_EQ(1, active_streams_->value());
  ASSERT_EQ(1, handle1->streamId());
  auto handle2 = st->onStreamBegin(2, conn2, *testCallbacks2, *testCallbacks2);
  ASSERT_EQ(2, active_streams_->value());
  ASSERT_EQ(2, handle2->streamId());

  CHECK_CALLED({
    st->tryLock(1, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_TRUE(sc.has_value());
      EXPECT_EQ(1, sc->streamId());
      EXPECT_EQ(&sc->streamCallbacks(), &static_cast<StreamCallbacks&>(*testCallbacks1));
      EXPECT_EQ(&sc->eventCallbacks(), &static_cast<ChannelEventCallbacks&>(*testCallbacks1));
      EXPECT_EQ(&sc->connection(), &static_cast<Network::Connection&>(conn1));
    });
  });
  CHECK_CALLED({
    st->tryLock(2, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_TRUE(sc.has_value());
      EXPECT_EQ(2, sc->streamId());
    });
  });
  CHECK_CALLED({
    st->tryLock(3, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });

  handle1.reset();
  ASSERT_EQ(1, active_streams_->value());

  CHECK_CALLED({
    st->tryLock(1, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });
  CHECK_CALLED({
    st->tryLock(2, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_TRUE(sc.has_value());
      EXPECT_EQ(2, sc->streamId());
    });
  });
  CHECK_CALLED({
    st->tryLock(3, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });

  handle2.reset();
  ASSERT_EQ(0, active_streams_->value());

  CHECK_CALLED({
    st->tryLock(1, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });
  CHECK_CALLED({
    st->tryLock(2, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });
  CHECK_CALLED({
    st->tryLock(3, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });
}

class StreamTrackerThreadingTest : public testing::Test,
                                   public Event::TestUsingSimulatedTime,
                                   public Thread::RealThreadsTestHelper {
public:
  static constexpr size_t num_threads = 4;
  StreamTrackerThreadingTest()
      : Envoy::Thread::RealThreadsTestHelper(num_threads) {
    ON_CALL(context.server_factory_context_, threadLocal())
      .WillByDefault(testing::ReturnRef(tls()));
    ON_CALL(context.server_factory_context_, api()).WillByDefault(testing::ReturnRef(api()));
    ON_CALL(context.server_factory_context_, mainThreadDispatcher()).WillByDefault(ReturnRef(*main_dispatcher_));
    runOnMainBlocking([&] {
      stream_tracker_ = StreamTracker::fromContext(context.server_factory_context_);
      // Note: context.store_ and context.server_factory_context_.store_ are NOT the same!
      active_streams_ = context.server_factory_context_.store_.findGaugeByString("ssh.active_streams");
      total_streams_ = context.server_factory_context_.store_.findCounterByString("ssh.total_streams");
      EXPECT_EQ(&active_streams_->get(), &stream_tracker_->stats().active_streams_);
      EXPECT_EQ(&total_streams_->get(), &stream_tracker_->stats().total_streams_);
    });
  }

  ~StreamTrackerThreadingTest() {
    std::weak_ptr<StreamTracker> wp = stream_tracker_;
    ASSERT(!wp.expired());
    runOnMainBlocking([&] { stream_tracker_.reset(); });
    shutdownThreading();
    exitThreads();
    ASSERT(wp.expired());
  }

  std::shared_ptr<StreamTracker> stream_tracker_;
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  Stats::GaugeOptConstRef active_streams_;
  Stats::CounterOptConstRef total_streams_;
};

TEST_F(StreamTrackerThreadingTest, ThreadSafety_Serial) {
  // Test creating all streams at once and deleting all streams at once

  absl::BitGen rng;

  ConditionalInitializer beginStreams, endStreams;
  absl::BlockingCounter beginWait(static_cast<int>(thread_dispatchers_.size()));
  absl::BlockingCounter endWait(static_cast<int>(thread_dispatchers_.size()));

  for (Event::DispatcherPtr& thread_dispatcher : thread_dispatchers_) {
    thread_dispatcher->post([&] {
      auto testCallbacks = std::make_shared<TestStreamCallbacks>();
      testing::NiceMock<Network::MockConnection> conn;
      ON_CALL(conn, dispatcher).WillByDefault(ReturnRef(*thread_dispatcher));
      auto id = absl::Uniform<stream_id_t>(rng);
      beginStreams.wait();

      auto handle = stream_tracker_->onStreamBegin(id, conn, *testCallbacks, *testCallbacks);
      EXPECT_EQ(id, handle->streamId());
      beginWait.DecrementCount();

      endStreams.wait();
      handle.reset();
      endWait.DecrementCount();
    });
  }

  // Note: don't use ASSERT_* here, failing asserts can skip over calls to setReady
  EXPECT_EQ(0, active_streams_->get().value());
  EXPECT_EQ(0, total_streams_->get().value());
  beginStreams.setReady();
  beginWait.Wait();
  EXPECT_EQ(num_threads, active_streams_->get().value());
  EXPECT_EQ(num_threads, total_streams_->get().value());
  endStreams.setReady();
  endWait.Wait();
  EXPECT_EQ(0, active_streams_->get().value());
  EXPECT_EQ(num_threads, total_streams_->get().value());
}

TEST_F(StreamTrackerThreadingTest, ThreadSafety_Mixed) {
  // Test mixed create and delete operations at the same time
  absl::BitGen rng;

  ConditionalInitializer beginStreams;
  absl::BlockingCounter endWait(static_cast<int>(thread_dispatchers_.size()));
  for (Event::DispatcherPtr& thread_dispatcher : thread_dispatchers_) {
    thread_dispatcher->post([&] {
      auto testCallbacks = std::make_shared<TestStreamCallbacks>();
      testing::NiceMock<Network::MockConnection> conn;
      ON_CALL(conn, dispatcher).WillByDefault(ReturnRef(*thread_dispatcher));
      auto id = absl::Uniform<stream_id_t>(rng);
      beginStreams.wait();

      for (int i = 0; i < 100; i++) {
        auto handle = stream_tracker_->onStreamBegin(id, conn, *testCallbacks, *testCallbacks);
        EXPECT_NE(nullptr, handle); // let the handle go out of scope immediately
      }

      endWait.DecrementCount();
    });
  }
  beginStreams.setReady();
  endWait.Wait();
  EXPECT_EQ(0, active_streams_->get().value());
  EXPECT_EQ(100 * num_threads, total_streams_->get().value());
}

TEST_F(StreamTrackerThreadingTest, ThreadSafety_TryLockRace) {
  // Ensure that if an active connection handle is deleted between the time it is fetched in tryLock
  // and the time the callback is invoked in the connection's thread, the callback will be passed
  // an empty context.
  absl::Notification handleCreated;
  absl::Notification destroyHandle;
  thread_dispatchers_[0]->post([&] {
    auto testCallbacks = std::make_shared<TestStreamCallbacks>();
    testing::NiceMock<Network::MockConnection> conn;
    ON_CALL(conn, dispatcher).WillByDefault(ReturnRef(*thread_dispatchers_[0]));
    auto testCallbacks1 = std::make_shared<TestStreamCallbacks>();
    testing::NiceMock<Network::MockConnection> conn1;
    auto handle1 = stream_tracker_->onStreamBegin(1, conn1, *testCallbacks1, *testCallbacks1);
    handleCreated.Notify();
    destroyHandle.WaitForNotification();
  });

  CHECK_CALLED({
    absl::Notification done;

    thread_dispatchers_[1]->post([&] {
      handleCreated.WaitForNotification();
      stream_tracker_->tryLock(1, [&](Envoy::OptRef<StreamContext> sc) {
        CALLED;
        EXPECT_FALSE(sc.has_value());
      });

      // post another event to the target dispatcher which will run after the callback passed to
      // tryLock above is done. however, both should be blocked on the destroyHandle notification
      thread_dispatchers_[0]->post([&] {
        done.Notify();
      });
    });

    // handle goes out of scope after destroyHandle is notified, then the tryLock callback runs
    destroyHandle.Notify();

    done.WaitForNotification();

    EXPECT_EQ(0, active_streams_->get().value());
    EXPECT_EQ(1, total_streams_->get().value());
  });
}

struct TestThreadLocalData : ThreadLocal::ThreadLocalObject {
  testing::NiceMock<Network::MockConnection> conn;
  std::shared_ptr<TestStreamCallbacks> callbacks;
  stream_id_t id{};

  StreamHandlePtr handle_;
};

TEST_F(StreamTrackerThreadingTest, NonBlockingTryLock) {
  auto slot = ThreadLocal::TypedSlot<TestThreadLocalData>::makeUnique(tls());

  std::unordered_map<Event::Dispatcher*, stream_id_t> ids;
  for (size_t tid = 0; tid < thread_dispatchers_.size(); tid++) {
    ids.insert({thread_dispatchers_[tid].get(), tid});
  }

  // Set up thread-local state on each worker
  slot->set([&ids](Event::Dispatcher& d) {
    auto tld = std::make_shared<TestThreadLocalData>();
    tld->callbacks = std::make_shared<TestStreamCallbacks>();
    ON_CALL(tld->conn, dispatcher).WillByDefault(ReturnRef(d));
    tld->id = ids[&d];
    return tld;
  });

  // Start a stream on each worker
  absl::BlockingCounter syncWait(num_threads);
  runOnAllWorkersBlocking([&] {
    auto& tld = *slot->get();
    ASSERT_EQ(nullptr, tld.handle_);
    tld.handle_ = stream_tracker_->onStreamBegin(tld.id, tld.conn, *tld.callbacks, *tld.callbacks, [&syncWait] {
      syncWait.DecrementCount();
    });
  });

  // Wait for thread-local data updates to be propagated to all workers. Calls to onStreamBegin
  // post additional callbacks to each worker.
  syncWait.Wait();
  ASSERT_EQ(num_threads, active_streams_->get().value());
  ASSERT_EQ(num_threads, total_streams_->get().value());

  // Each worker now has one associated stream. When other threads call tryLock for a stream owned
  // by a different thread, it should post a request to the owning thread which will invoke the
  // callback on that thread. This should not block the requesting thread.

  // First, post a callback to the target thread that blocks, so the event queue is held up
  absl::Notification wait;
  thread_dispatchers_[0]->post([&] {
    wait.WaitForNotification();
  });

  // Now on every other thread, call tryLock() on stream 0 at the same time
  absl::Barrier startBarrier(num_threads - 1);
  absl::BlockingCounter endPostWait(num_threads - 1);
  absl::BlockingCounter endRunWait(num_threads - 1);

  for (size_t tid = 1; tid < num_threads; tid++) {
    //              ^
    thread_dispatchers_[tid]->post([&] {
      startBarrier.Block();
      stream_tracker_->tryLock(0, [&](Envoy::OptRef<StreamContext> cb) {
        EXPECT_TRUE(cb.has_value());
        EXPECT_TRUE(thread_dispatchers_[0]->isThreadSafe());
        EXPECT_EQ(0, cb->streamId());
        endRunWait.DecrementCount();
      });
      endPostWait.DecrementCount();
    });
  }
  endPostWait.Wait();

  // Only thread 0 should be blocked now, with the following events (oldest first):
  //  [wait.WaitForNotification()] <- blocked here
  //  [tryLock(0)]
  //  [tryLock(0)]
  //  [tryLock(0)]

  // Unblock the event
  wait.Notify();

  // The tryLock events should all run (order is not guaranteed)
  endRunWait.Wait();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec