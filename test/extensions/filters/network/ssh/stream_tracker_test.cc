#include "source/extensions/filters/network/ssh/stream_tracker.h"

#include "test/test_common/utility.h"
#include "absl/synchronization/blocking_counter.h"
#include "test/test_common/test_common.h"
#include "test/mocks/server/server_factory_context.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class StreamTrackerTest : public testing::Test {
public:
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;
};

TEST_F(StreamTrackerTest, FromContextWithConfig) {
  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);
  ASSERT_EQ(0uz, st->numActiveConnectionHandles());
}

TEST_F(StreamTrackerTest, FromContextWithNoConfig) {
  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
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

TEST_F(StreamTrackerTest, TrackStream) {
  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);

  auto testCallbacks1 = std::make_shared<TestStreamCallbacks>();
  auto testCallbacks2 = std::make_shared<TestStreamCallbacks>();

  testing::NiceMock<Network::MockConnection> conn1;
  testing::NiceMock<Network::MockConnection> conn2;

  auto handle1 = st->onStreamBegin(1, conn1, *testCallbacks1, *testCallbacks1);
  ASSERT_EQ(1, st->numActiveConnectionHandles());
  ASSERT_EQ(1, handle1->streamId());
  auto handle2 = st->onStreamBegin(2, conn2, *testCallbacks2, *testCallbacks2);
  ASSERT_EQ(2, st->numActiveConnectionHandles());
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

  st->onStreamEnd(1);
  ASSERT_EQ(1, st->numActiveConnectionHandles());

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

  st->onStreamEnd(2);
  ASSERT_EQ(0, st->numActiveConnectionHandles());

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

TEST_F(StreamTrackerTest, TrackStream_EndWithHandle) {
  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);

  auto testCallbacks1 = std::make_shared<TestStreamCallbacks>();
  auto testCallbacks2 = std::make_shared<TestStreamCallbacks>();

  testing::NiceMock<Network::MockConnection> conn1;
  testing::NiceMock<Network::MockConnection> conn2;

  auto handle1 = st->onStreamBegin(1, conn1, *testCallbacks1, *testCallbacks1);
  ASSERT_EQ(1, st->numActiveConnectionHandles());
  auto handle2 = st->onStreamBegin(2, conn2, *testCallbacks2, *testCallbacks2);
  ASSERT_EQ(2, st->numActiveConnectionHandles());

  CHECK_CALLED({
    st->tryLock(1, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_TRUE(sc.has_value());
      EXPECT_EQ(1, sc->streamId());
    });
  });
  CHECK_CALLED({ st->tryLock(2, [&](Envoy::OptRef<StreamContext> sc) {
                   CALLED;
                   ASSERT_TRUE(sc.has_value());
                   EXPECT_EQ(2, sc->streamId());
                 }); });
  CHECK_CALLED({
    st->tryLock(3, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });
  handle1.reset();
  ASSERT_EQ(1, st->numActiveConnectionHandles());

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
  ASSERT_EQ(0, st->numActiveConnectionHandles());

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

TEST_F(StreamTrackerTest, TrackStream_ThreadSafety_Serial) {
  // Test creating all streams at once and deleting all streams at once

  Thread::ThreadFactory& thread_factory = Thread::threadFactoryForTest();

  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);

  constexpr int num_threads = 20;
  std::vector<Thread::ThreadPtr> threads;
  threads.reserve(num_threads);
  ConditionalInitializer beginStreams, endStreams;
  absl::BlockingCounter beginWait(num_threads);
  absl::BlockingCounter endWait(num_threads);
  for (int i = 0; i < num_threads; ++i) {
    threads.push_back(thread_factory.createThread([i, &st, &beginStreams, &endStreams, &beginWait, &endWait]() {
      auto testCallbacks = std::make_shared<TestStreamCallbacks>();
      testing::NiceMock<Network::MockConnection> conn;

      beginStreams.wait();
      auto handle = st->onStreamBegin(i, conn, *testCallbacks, *testCallbacks);
      ASSERT_EQ(i, handle->streamId());
      beginWait.DecrementCount();

      endStreams.wait();
      handle.reset();
      endWait.DecrementCount();
    }));
  }
  ASSERT_EQ(0, st->numActiveConnectionHandles());
  beginStreams.setReady();
  beginWait.Wait();
  ASSERT_EQ(num_threads, st->numActiveConnectionHandles());
  endStreams.setReady();
  endWait.Wait();
  ASSERT_EQ(0, st->numActiveConnectionHandles());
  for (auto& thread : threads) {
    thread->join();
  }
}

TEST_F(StreamTrackerTest, TrackStream_ThreadSafety_Mixed) {
  // Test mixed create and delete operations at the same time

  Thread::ThreadFactory& thread_factory = Thread::threadFactoryForTest();

  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);

  constexpr int num_threads = 20;
  std::vector<Thread::ThreadPtr> threads;
  threads.reserve(num_threads);
  ConditionalInitializer beginStreams;
  for (int i = 0; i < num_threads; ++i) {
    threads.push_back(thread_factory.createThread([i, &st, &beginStreams]() {
      auto testCallbacks = std::make_shared<TestStreamCallbacks>();
      testing::NiceMock<Network::MockConnection> conn;

      beginStreams.wait();
      auto handle = st->onStreamBegin(i, conn, *testCallbacks, *testCallbacks);
      EXPECT_NE(nullptr, handle); // let the handle go out of scope immediately
    }));
  }
  ASSERT_EQ(0, st->numActiveConnectionHandles());
  beginStreams.setReady();
  for (auto& thread : threads) {
    thread->join();
  }
  ASSERT_EQ(0, st->numActiveConnectionHandles());
}

TEST_F(StreamTrackerTest, TrackStream_ThreadSafety_TryLockRace) {
  // Ensure that if an active connection handle is deleted between the time it is fetched in tryLock
  // and the time the callback is invoked in the connection's thread, the callback will be passed
  // an empty context.

  StreamTrackerConfig cfg;
  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);

  auto testCallbacks1 = std::make_shared<TestStreamCallbacks>();
  testing::NiceMock<Network::MockConnection> conn1;
  auto handle1 = st->onStreamBegin(1, conn1, *testCallbacks1, *testCallbacks1);

  EXPECT_CALL(conn1.dispatcher_, post(_))
    .WillOnce([&](Event::PostCb cb) {
      // StreamTracker::mu_ has been released and will be acquired again when cb() runs
      handle1.reset(); // the stream should be deleted
      cb();
    });

  CHECK_CALLED({
    st->tryLock(1, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      EXPECT_FALSE(sc.has_value());
    });
  });
}

class MockStreamTrackerFilter : public StreamTrackerFilter {
public:
  MOCK_METHOD(void, onStreamBegin, (StreamContext&), (override));
  MOCK_METHOD(void, onStreamEnd, (StreamContext&), (override));
};

class MockStreamTrackerFilterFactory : public StreamTrackerFilterFactory {
public:
  std::string name() const override { return "mock_filter"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Protobuf::StringValue>();
  }
  StreamTrackerFilterPtr createStreamTrackerFilter(const Protobuf::Message&, Server::Configuration::ServerFactoryContext&) override {
    return std::make_unique<MockStreamTrackerFilter>();
  }
};

REGISTER_FACTORY(MockStreamTrackerFilterFactory, StreamTrackerFilterFactory);

TEST_F(StreamTrackerTest, Filters) {
  StreamTrackerConfig cfg;
  auto* filterCfg = cfg.add_filters();
  filterCfg->set_name("mock_filter");
  filterCfg->mutable_typed_config()->PackFrom(Protobuf::StringValue{});

  auto st = StreamTracker::fromContext(context, cfg);
  ASSERT_NE(nullptr, st);
  auto n = st->visitFiltersForTest([&](StreamTrackerFilter& f) {
    const auto& filter = dynamic_cast<const MockStreamTrackerFilter&>(f);
    EXPECT_CALL(filter, onStreamBegin)
      .WillOnce([](StreamContext& ctx) {
        EXPECT_EQ(1, ctx.streamId());
      });
    EXPECT_CALL(filter, onStreamEnd);
  });
  ASSERT_EQ(1, n);

  auto testCallbacks1 = std::make_shared<TestStreamCallbacks>();
  testing::NiceMock<Network::MockConnection> conn1;

  auto handle = st->onStreamBegin(1, conn1, *testCallbacks1, *testCallbacks1);
  st->onStreamEnd(1);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec