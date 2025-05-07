#pragma once

#include "test/test_common/test_common.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Api {
class MockApi;
}
namespace Envoy::Filesystem {
class MockInstance;
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {
inline const auto serverEd25519HostKey = openssh::SSHKey::generate(KEY_ED25519, 256);
inline const auto clientEd25519HostKey = openssh::SSHKey::generate(KEY_ED25519, 256);
inline const auto serverRsaHostKey = openssh::SSHKey::generate(KEY_RSA, 2048);
inline const auto clientRsaHostKey = openssh::SSHKey::generate(KEY_RSA, 2048);
inline const auto userCaKey = openssh::SSHKey::generate(KEY_ED25519, 256);

inline const std::map<std::string, std::string> test_file_contents = {
  {"server/test_host_ed25519_key", *(*serverEd25519HostKey)->toPrivateKeyPem()},
  {"server/test_host_ed25519_key.pub", *(*serverEd25519HostKey)->toPublicKeyPem()},
  {"server/test_host_rsa_key", *(*serverRsaHostKey)->toPrivateKeyPem()},
  {"server/test_host_rsa_key.pub", *(*serverRsaHostKey)->toPublicKeyPem()},
  {"server/test_user_ca_key", *(*userCaKey)->toPrivateKeyPem()},
  {"server/test_user_ca_key.pub", *(*userCaKey)->toPublicKeyPem()},

  {"client/test_host_ed25519_key", *(*clientEd25519HostKey)->toPrivateKeyPem()},
  {"client/test_host_ed25519_key.pub", *(*clientEd25519HostKey)->toPublicKeyPem()},
  {"client/test_host_rsa_key", *(*serverRsaHostKey)->toPrivateKeyPem()},
  {"client/test_host_rsa_key.pub", *(*serverRsaHostKey)->toPublicKeyPem()},

};

void setupMockFilesystem(NiceMock<Api::MockApi>& api, NiceMock<Filesystem::MockInstance>& file_system);
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec