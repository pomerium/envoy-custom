#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

MockTransportCallbacks::MockTransportCallbacks() {
  EXPECT_CALL(mock_scope_, createScope_)
    .Times(testing::AnyNumber());
  ON_CALL(*this, statsScope)
    .WillByDefault(testing::ReturnRef(mock_scope_));
}
MockTransportCallbacks::~MockTransportCallbacks() {}

MockDownstreamTransportCallbacks::MockDownstreamTransportCallbacks() {}
MockDownstreamTransportCallbacks::~MockDownstreamTransportCallbacks() {}

MockUpstreamTransportCallbacks::MockUpstreamTransportCallbacks() {}
MockUpstreamTransportCallbacks::~MockUpstreamTransportCallbacks() {}

MockKexCallbacks::MockKexCallbacks() {}
MockKexCallbacks::~MockKexCallbacks() {}

MockDirectionalPacketCipher::MockDirectionalPacketCipher() {}
MockDirectionalPacketCipher::~MockDirectionalPacketCipher() {}

MockSshMessageHandler::MockSshMessageHandler() {}
MockSshMessageHandler::~MockSshMessageHandler() {}

MockSshMessageMiddleware::MockSshMessageMiddleware() {}
MockSshMessageMiddleware::~MockSshMessageMiddleware() {}

MockStreamMgmtServerMessageHandler::MockStreamMgmtServerMessageHandler() {}
MockStreamMgmtServerMessageHandler::~MockStreamMgmtServerMessageHandler() {}

MockChannelStreamCallbacks::MockChannelStreamCallbacks() {}
MockChannelStreamCallbacks::~MockChannelStreamCallbacks() {}

MockHijackedChannelCallbacks::MockHijackedChannelCallbacks() {}
MockHijackedChannelCallbacks::~MockHijackedChannelCallbacks() {}

MockChannel::MockChannel() {
  ON_CALL(*this, setChannelCallbacks)
    .WillByDefault([this](ChannelCallbacks& cb) {
      return this->Channel::setChannelCallbacks(cb);
    });
}
MockChannel::~MockChannel() {
  Die();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec