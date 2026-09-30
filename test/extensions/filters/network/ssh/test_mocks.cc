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
      this->Channel::setChannelCallbacks(cb);
    });
}
MockChannel::~MockChannel() {
  if (expect_set_channel_callbacks_never_called_) {
    EXPECT_TRUE(callbacks_ == nullptr)
      << "test bug: expectSetChannelCallbacksNeverCalled was called, but callbacks_ is not null";
  } else {
    EXPECT_TRUE(callbacks_ != nullptr)
      << "test bug: non-default setChannelCallbacks handler is missing call to base class Channel::setChannelCallbacks\n"
         "(if it is expected that setChannelCallbacks is never called, call expectSetChannelCallbacksNeverCalled())";
  }
  Die();
}
void MockChannel::expectSetChannelCallbacksNeverCalled() {
  EXPECT_CALL(*this, setChannelCallbacks).Times(0);
  expect_set_channel_callbacks_never_called_ = true;
}

MockChannelStatsProvider::MockChannelStatsProvider() {}
MockChannelStatsProvider::~MockChannelStatsProvider() {}

MockChannelFilterCallbacks::MockChannelFilterCallbacks() {}
MockChannelFilterCallbacks::~MockChannelFilterCallbacks() {}

MockChannelFilter::MockChannelFilter() {}
MockChannelFilter::~MockChannelFilter() {}

MockChannelFilterFactory::MockChannelFilterFactory() {}
MockChannelFilterFactory::~MockChannelFilterFactory() {}

MockChannelFilterFactoryConfig::MockChannelFilterFactoryConfig() {}
MockChannelFilterFactoryConfig::~MockChannelFilterFactoryConfig() {}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec