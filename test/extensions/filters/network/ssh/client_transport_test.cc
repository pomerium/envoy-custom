#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/mocks/server/factory_context.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/test_common.h"
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {

static const std::map<std::string, std::string> test_file_contents = {
  {"test_host_ed25519_key", R"(
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCnlt7mHz2GsNIioQ04NvcLvTsZ5cSJuVGJ64VQkASNkwAAAJCuKJGCriiR
ggAAAAtzc2gtZWQyNTUxOQAAACCnlt7mHz2GsNIioQ04NvcLvTsZ5cSJuVGJ64VQkASNkw
AAAEAO706AzVFuW/ua4hGiKZzK5PDATB+tmqWbEAQrrs3/QqeW3uYfPYaw0iKhDTg29wu9
OxnlxIm5UYnrhVCQBI2TAAAADHVidW50dUBidWlsZAE=
-----END OPENSSH PRIVATE KEY-----
)"},
  {"test_host_ed25519_key.pub", R"(
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeW3uYfPYaw0iKhDTg29wu9OxnlxIm5UYnrhVCQBI2T
)"},
  {"test_host_rsa_key", R"(
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
)"},
  {"test_host_rsa_key.pub", R"(
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSGuI6niJvb7nCa7xtaufN76/f/sfSIMU93XyLJj74WXzMaHxdCFii++Volkw"
"0GAgpbgSqtzZKpulPO3g1HjVMzjqLxWvIlPyNLkw++MQVm+OJfJtLrn7ygqUhe9o0t0knxQOqoHlTJdqOEQT+UeKoXi4lpfUDT"
"ZKiY7ukro1qM7HHepTtfliTDySYrCpXkZ+vOSCv+eQkrCMP1vd75jhOTtewtG/+vruY3jAXTloBAKLSgzihmuEWd7KsQcRpZoM"
"xy+c5spFP2vwfaiC6FOQ74Y87UKq97k518DeT3b/47VUiumVQswSQLgVdrs1M2l19engHilvlOZlwYXXBUWmppfGwpRzsqahn/"
"3i7entwwh9LTp625y9KPGVwROlxeNU+ZdWzg1tw15sFgKekzvguvDc/rUQpN+mBEgEHG+BxH/QIGtBASx48L43nW4EL6KAjimP"
"HMFuF3Yb//yex1IJyrBhbQ0VN4WXbViuhekWDIS7xLpXbbvT+++NfxzKM9QE=
)"},
  {"test_user_ca_key", R"(
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDDLIrjPSZGX9lRO7HhqNDlEOmq/o/x4bBk/YY8OpMSBgAAAJA5xd8JOcXf
CQAAAAtzc2gtZWQyNTUxOQAAACDDLIrjPSZGX9lRO7HhqNDlEOmq/o/x4bBk/YY8OpMSBg
AAAEC0wHL5Plt3Pl6n5ZMQ3YZbm8DrJzQJ3T6PCCW4UzmX38MsiuM9JkZf2VE7seGo0OUQ
6ar+j/HhsGT9hjw6kxIGAAAADHVidW50dUBidWlsZAE=
-----END OPENSSH PRIVATE KEY-----
)"},
  {"test_user_ca_key.pub", R"(
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMsiuM9JkZf2VE7seGo0OUQ6ar+j/HhsGT9hjw6kxIG
)"},
};

class ClientTransportTest : public testing::Test {
public:
  ClientTransportTest() {
    EXPECT_CALL(api_.file_system_, fileReadToEnd(_))
      .WillRepeatedly([](const std::string& filename) {
        return absl::StatusOr<std::string>{test_file_contents.at(filename)};
      });

    initializeCodec();
  }

  void initializeCodec() {

    auto config = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
    auto* hostKey1 = config->add_host_keys();
    *hostKey1->mutable_private_key_file() = "test_host_ed25519_key";
    *hostKey1->mutable_public_key_file() = "test_host_ed25519_key.pub";
    auto* hostKey2 = config->add_host_keys();
    *hostKey2->mutable_private_key_file() = "test_host_rsa_key";
    *hostKey2->mutable_public_key_file() = "test_host_rsa_key.pub";
    *config->mutable_user_ca_key()->mutable_private_key_file() = "test_user_ca_key";
    *config->mutable_user_ca_key()->mutable_public_key_file() = "test_user_ca_key.pub";

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