#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_config.h"
#include "test/extensions/filters/network/ssh/test_data.h"
#include "test/mocks/server/factory_context.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/test_common.h"
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {

class ClientTransportTest : public testing::Test {
public:
  ClientTransportTest() {
    setupMockFilesystem(api_);
    initializeCodec();
  }

  void initializeCodec() {

    auto config = newConfig();
    configureKeys(config);

    tls_slot_ = ThreadLocal::TypedSlot<ThreadLocalData>::makeUnique(tls_allocator_);
    // codec_ = std::make_unique<SshClientTransport>(api_, config, tls_slot_);
    // codec_->setCodecCallbacks(codec_callbacks_);
  }

  std::unique_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> tls_slot_;
  NiceMock<Api::MockApi> api_;
  ThreadLocal::MockInstance tls_allocator_;
  NiceMock<MockServerCodecCallbacks> codec_callbacks_;
  NiceMock<Network::MockServerConnection> mock_connection_;
  std::unique_ptr<SshClientTransport> codec_;
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec