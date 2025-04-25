#include "source/extensions/filters/network/ssh/transport_base.h"
#include "test/extensions/filters/network/ssh/test_data.h"
#include "test/mocks/server/factory_context.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/test_common.h"
#include "test/extensions/filters/network/ssh/test_config.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "source/extensions/filters/network/ssh/kex.h"

#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {

class ServerKexTest : public testing::Test {
public:
  ServerKexTest() {
    setupMockFilesystem(api_);
    config_ = newConfig();
    configureKeys(config_);

    kex_ = std::make_unique<Kex>(transport_, transport_, KexMode::Server);
  }

private:
  NiceMock<Api::MockApi> api_;
  std::shared_ptr<CodecConfig> config_;

  testing::StrictMock<MockTransport<MockServerCodec>> transport_;
  std::unique_ptr<Kex> kex_;
};

// TEST_F(ServerKexTest, )

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec