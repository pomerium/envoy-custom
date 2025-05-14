#include "source/common/math.h"
#include "gtest/gtest.h"

namespace test {

TEST(SubSatTest, SubSat) {
  EXPECT_EQ(1, sub_sat(static_cast<uint32_t>(10), static_cast<uint32_t>(9)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(10), static_cast<uint32_t>(10)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(10), static_cast<uint32_t>(11)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(0), static_cast<uint32_t>(1)));
  EXPECT_EQ(0, sub_sat(static_cast<uint32_t>(0), static_cast<uint32_t>(0)));
  EXPECT_EQ(1, sub_sat(static_cast<uint32_t>(1), static_cast<uint32_t>(0)));
}

} // namespace test