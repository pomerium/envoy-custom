#include "test/extensions/filters/network/ssh/test_mocks.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

MockTransportCallbacks::MockTransportCallbacks() {}
MockTransportCallbacks::~MockTransportCallbacks() {}

MockKexCallbacks::MockKexCallbacks() {}
MockKexCallbacks::~MockKexCallbacks() {}

MockDirectionalPacketCipher::MockDirectionalPacketCipher() {}
MockDirectionalPacketCipher::~MockDirectionalPacketCipher() {}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec