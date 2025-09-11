#include "source/common/math.h"
#include "gtest/gtest.h"
#include <limits>

namespace test {

TEST(SubSatTest, SubSat) {
  EXPECT_EQ(1, sub_sat(static_cast<uint32_t>(10), static_cast<uint32_t>(9)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(10), static_cast<uint32_t>(10)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(10), static_cast<uint32_t>(11)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(0), static_cast<uint32_t>(1)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(0), static_cast<uint32_t>(0)));
  EXPECT_EQ(1, sub_sat(static_cast<uint32_t>(1), static_cast<uint32_t>(0)));
}

TEST(SubOverflowTest, SubOverflow) {
  {
    uint32_t x = 10;
    EXPECT_EQ(false, sub_overflow(&x, 1u));
    EXPECT_EQ(9, x);
  }
  {
    uint32_t x = 0;
    EXPECT_EQ(true, sub_overflow(&x, 1u));
    EXPECT_EQ(std::numeric_limits<uint32_t>::max(), x);
  }
  {
    uint32_t x = 10;
    EXPECT_EQ(true, sub_overflow(&x, 20u));
    EXPECT_EQ(std::numeric_limits<uint32_t>::max() - 9, x);
  }
}

TEST(SubOverflowTest, AddOverflow) {
  {
    uint32_t x = std::numeric_limits<uint32_t>::max() - 10;
    EXPECT_EQ(false, add_overflow(&x, 1u));
    EXPECT_EQ(std::numeric_limits<uint32_t>::max() - 9, x);
  }
  {
    uint32_t x = std::numeric_limits<uint32_t>::max();
    EXPECT_EQ(true, add_overflow(&x, 1u));
    EXPECT_EQ(0, x);
  }
  {
    uint32_t x = std::numeric_limits<uint32_t>::max() - 10;
    EXPECT_EQ(true, add_overflow(&x, 20u));
    EXPECT_EQ(9, x);
  }
}

} // namespace test