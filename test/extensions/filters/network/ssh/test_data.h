#pragma once

#include "test/mocks/api/mocks.h"
#include "test/extensions/filters/network/ssh/test_common.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {
inline const auto ed25519HostKey = openssh::SSHKey::generate(KEY_ED25519, 256);
inline const auto rsaHostKey = openssh::SSHKey::generate(KEY_RSA, 2048);
inline const auto userCaKey = openssh::SSHKey::generate(KEY_ED25519, 256);

inline const std::map<std::string, std::string> test_file_contents = {
  {"test_host_ed25519_key", *ed25519HostKey->toPrivateKeyPem()},
  {"test_host_ed25519_key.pub", *ed25519HostKey->toPublicKeyPem()},
  {"test_host_rsa_key", *rsaHostKey->toPrivateKeyPem()},
  {"test_host_rsa_key.pub", *rsaHostKey->toPublicKeyPem()},
  {"test_user_ca_key", *ed25519HostKey->toPrivateKeyPem()},
  {"test_user_ca_key.pub", *ed25519HostKey->toPublicKeyPem()},
};

inline void setupMockFilesystem(NiceMock<Api::MockApi>& api) {
  EXPECT_CALL(api.file_system_, fileReadToEnd(_))
    .WillRepeatedly([](const std::string& filename) {
      return absl::StatusOr<std::string>{test_file_contents.at(filename)};
    });
}
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec