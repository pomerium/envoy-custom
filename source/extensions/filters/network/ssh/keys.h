#pragma once

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "source/common/common/utility.h"
#include "source/extensions/filters/network/ssh/util.h"
#include <netinet/in.h>

extern "C" {
#include "openssh/authfile.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

inline libssh::SshKeyPtr loadSshPrivateKey(const char* filename) {
  sshkey* key{};
  auto ret = sshkey_load_private(filename, nullptr, &key, nullptr);
  if (ret != 0) {
    ExceptionUtil::throwEnvoyException("error reading ssh private key");
  }
  return libssh::SshKeyPtr(key);
}

inline libssh::SshKeyPtr loadSshPublicKey(const char* filename) {
  sshkey* key{};
  auto ret = sshkey_load_public(filename, &key, nullptr);
  if (ret < 0) {
    ExceptionUtil::throwEnvoyException("error reading ssh private key");
  }
  return libssh::SshKeyPtr(key);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec