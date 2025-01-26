#pragma once

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "absl/strings/str_split.h"
#include "source/common/common/base64.h"
#include "source/extensions/filters/network/ssh/util.h"
#include <netinet/in.h>

extern "C" {
#include "openssh/authfile.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// Parses a ssh-rsa public key file.
inline bssl::UniquePtr<EVP_PKEY> parseRsaPublicKey(std::string pubKeyFileContents) {
  std::vector<std::string> segments = absl::StrSplit(pubKeyFileContents, absl::ByAsciiWhitespace{});
  if (segments.size() < 2) {
    throw EnvoyException("not an ssh public key");
  }
  auto type = segments[0];
  auto encodedKey = segments[1];

  auto decoded = Envoy::Base64::decode(encodedKey);
  if (decoded.empty()) {
    throw EnvoyException("invalid base64 data");
  }

  constexpr auto ssh_rsa_hdr = "ssh-rsa";
  if (!decoded.starts_with(ssh_rsa_hdr)) {
    throw EnvoyException("not an ssh-rsa public key");
  }
  // RFC4253 § 6.6
  auto data = reinterpret_cast<const uint8_t*>(decoded.data() +
                                               std::char_traits<char>::length(ssh_rsa_hdr));
  const uint32_t esize = ntohl(*reinterpret_cast<uint32_t*>(const_cast<uint8_t*>(data)));
  data += sizeof(esize);
  auto e = BN_bin2bn(data, esize, nullptr);
  data += esize;
  const uint32_t nsize = ntohl(*reinterpret_cast<uint32_t*>(const_cast<uint8_t*>(data)));
  data += sizeof(nsize);
  auto n = BN_bin2bn(data, nsize, nullptr);

  bssl::UniquePtr<EVP_PKEY> pubkey;
  EVP_PKEY_assign_RSA(pubkey.get(), RSA_new_public_key(n, e));
  return pubkey;
}

inline libssh::SshKeyPtr loadSshPrivateKey(const char* filename) {
  sshkey* key{};
  auto ret = sshkey_load_private(filename, nullptr, &key, nullptr);
  if (ret != 0) {
    throw EnvoyException("error reading ssh private key");
  }
  return libssh::SshKeyPtr(key);
}

inline libssh::SshKeyPtr loadSshPublicKey(const char* filename) {
  sshkey* key{};
  auto ret = sshkey_load_public(filename, &key, nullptr);
  if (ret < 0) {
    throw EnvoyException("error reading ssh private key");
  }
  return libssh::SshKeyPtr(key);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec