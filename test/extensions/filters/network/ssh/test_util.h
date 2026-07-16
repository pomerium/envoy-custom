#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test::util {

inline void populateAuthContext(pomerium::extensions::ssh::AuthContext& dest,
                                const openssh::SSHKey& downstream_public_key,
                                bool populate_fake_session_info = true) {
  auto pkBlob = downstream_public_key.toPublicKeyBlob();
  dest.set_public_key(pkBlob.data(), pkBlob.size());
  dest.set_public_key_alg(downstream_public_key.keyTypeName());
  auto fp = downstream_public_key.rawFingerprint();
  dest.set_public_key_fingerprint_sha256(fp.data(), fp.size());

  if (populate_fake_session_info) {
    dest.set_session_binding_id("fake-session-binding-id");
    dest.set_session_id("fake-session-id");
    dest.set_user_id("fake-user-id");
  }
}

inline void populateAuthContext(pomerium::extensions::ssh::AuthContext& dest,
                                const pomerium::extensions::ssh::PublicKeyMethodRequest& downstream_public_key,
                                bool populate_fake_session_info = true) {
  dest.set_public_key(downstream_public_key.public_key());
  dest.set_public_key_alg(downstream_public_key.public_key_alg());
  dest.set_public_key_fingerprint_sha256(downstream_public_key.public_key_fingerprint_sha256());

  if (populate_fake_session_info) {
    dest.set_session_binding_id("fake-session-binding-id");
    dest.set_session_id("fake-session-id");
    dest.set_user_id("fake-user-id");
  }
}

} // namespace test::util
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec