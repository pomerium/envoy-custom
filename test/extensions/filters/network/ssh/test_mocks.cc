#include "test/extensions/filters/network/ssh/test_mocks.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

MockDirectionalPacketCipher::MockDirectionalPacketCipher() {}
MockDirectionalPacketCipher::~MockDirectionalPacketCipher() {}

MockSshMessageHandler::MockSshMessageHandler() {}
MockSshMessageHandler::~MockSshMessageHandler() {}

MockSshMessageMiddleware::MockSshMessageMiddleware() {}
MockSshMessageMiddleware::~MockSshMessageMiddleware() {}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec