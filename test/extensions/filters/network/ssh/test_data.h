#pragma once

#include "source/common/filesystem/filesystem_impl.h"

// openssh defines 'mkstemp', which clashes with envoy syscall mock classes
// https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/openbsd-compat.h#L152
#ifdef mkstemp
#undef mkstemp
#endif
#include "test/mocks/api/mocks.h"

#include "test/extensions/filters/network/ssh/test_common.h"
#include "source/extensions/filters/network/ssh/openssh.h"

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

inline void setupMockFilesystem(NiceMock<Api::MockApi>& api, NiceMock<Filesystem::MockInstance>& file_system) {
  EXPECT_CALL(api, fileSystem()).WillRepeatedly(ReturnRef(file_system));

  EXPECT_CALL(file_system, fileReadToEnd(_))
    .WillRepeatedly([](const std::string& filename) {
      return absl::StatusOr<std::string>{test_file_contents.at(filename)};
    });
}
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec