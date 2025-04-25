#pragma once

#include "test/extensions/filters/network/ssh/test_common.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

using pomerium::extensions::ssh::CodecConfig;

inline std::shared_ptr<CodecConfig> newConfig() {
  return std::make_shared<CodecConfig>();
}

inline void configureKeys(std::shared_ptr<CodecConfig>& config) {
  *config->add_host_keys() = "test_host_ed25519_key";
  *config->add_host_keys() = "test_host_rsa_key";
  *config->mutable_user_ca_key() = "test_user_ca_key";
}
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec