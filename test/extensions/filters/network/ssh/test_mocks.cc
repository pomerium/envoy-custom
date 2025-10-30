#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

MockTransportCallbacks::MockTransportCallbacks() {
  ON_CALL(*this, statsScope)
    .WillByDefault(testing::ReturnRef(*store_.rootScope()));
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
  ON_CALL(*this, supportsChannelStats)
    .WillByDefault(testing::Return(false));
}
MockChannel::~MockChannel() {
  Die();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec