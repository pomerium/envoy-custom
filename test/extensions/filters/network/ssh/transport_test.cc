#include "source/extensions/filters/network/ssh/transport.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

TEST(TransportTest, ForwardHeader) {
  testing::StrictMock<MockTransportCallbacks> callbacks;
  wire::Message msg{wire::DebugMsg{}};
  EXPECT_CALL(callbacks, forward(MSG(wire::DebugMsg, _), EffectiveHeader));
  callbacks.forwardHeader(std::move(msg), {});
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec