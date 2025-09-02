#include "test/extensions/filters/network/ssh/test_mocks.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

MockTransportCallbacks::MockTransportCallbacks() {}
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

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec