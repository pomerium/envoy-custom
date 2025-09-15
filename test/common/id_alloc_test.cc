#include "source/common/id_alloc.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace test {

TEST(IdAllocatorTest, AllocWithLimit) {
  IDAllocator<uint32_t> a{0, 10};
  // allocate up to the limit
  for (uint32_t i = 0; i < 10; i++) {
    auto id = a.alloc();
    ASSERT_OK(id.status());
    ASSERT_EQ(i, *id);
  }

  // additional IDs should error
  ASSERT_EQ(absl::ResourceExhaustedError("failed to allocate ID"), a.alloc().status());
  ASSERT_EQ(absl::ResourceExhaustedError("failed to allocate ID"), a.alloc().status());
}

TEST(IdAllocatorTest, StartId) {
  for (uint32_t i = 0; i < 10; i++) {
    IDAllocator<uint32_t> a(i);
    auto id = a.alloc();
    ASSERT_OK(id.status());
    ASSERT_EQ(i, *id);
    a.release(i);
  }
}

TEST(IdAllocatorTest, Release) {
  IDAllocator<uint32_t> a{0};
  for (uint32_t i = 0; i < 10; i++) {
    auto id = a.alloc();
    ASSERT_OK(id.status());
    ASSERT_EQ(i, *id);
  }

  // releasing and then allocating an ID should reuse freed IDs
  for (uint32_t i = 0; i < 10; i++) {
    a.release(i);
    auto id = a.alloc();
    ASSERT_OK(id.status());
    ASSERT_EQ(i, *id);
  }

  // releasing multiple IDs should re-allocate freed IDs in order
  for (uint32_t i = 0; i < 10; i++) {
    a.release(i);
  }
  for (uint32_t i = 0; i < 10; i++) {
    auto id = a.alloc();
    ASSERT_OK(id.status());
    ASSERT_EQ(i, *id);
  }
}

TEST(IdAllocatorTest, ReleaseDeathNeverAllocated) {
  IDAllocator<uint32_t> a{0};
  EXPECT_DEATH(a.release(0), "ID was never allocated or was already released");
}

TEST(IdAllocatorTest, ReleaseDeathLessThanStartID) {
  IDAllocator<uint32_t> a{1};
  EXPECT_DEATH(a.release(0), "ID was never allocated or was already released");
}

TEST(IdAllocatorTest, ReleaseDeathAlreadyFreed) {
  IDAllocator<uint32_t> a{0};
  ASSERT_EQ(0, *a.alloc());
  a.release(0);
  EXPECT_DEATH(a.release(0), "ID was never allocated or was already released");
}

} // namespace test