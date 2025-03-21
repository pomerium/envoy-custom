#pragma once

#include <cstdint> // IWYU pragma: keep
#include <cstdio>  // IWYU pragma: keep

#include "absl/status/statusor.h"

#include "source/common/common/c_smart_ptr.h"

#include "source/extensions/filters/network/ssh/common.h"

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/cipher.h"
#include "openssh/sshbuf.h"
}

namespace openssh {

using SshKeyPtr = Envoy::CSmartPtr<sshkey, sshkey_free>;
using SshBufPtr = Envoy::CSmartPtr<sshbuf, sshbuf_free>;
using SshCipherCtxPtr = Envoy::CSmartPtr<sshcipher_ctx, cipher_free>;

absl::StatusCode statusCodeFromErr(int n);
absl::Status statusFromErr(int n);

static constexpr auto ExtensionNoTouchRequired = "no-touch-required";
static constexpr auto ExtensionPermitX11Forwarding = "permit-X11-forwarding";
static constexpr auto ExtensionPermitPortForwarding = "permit-port-forwarding";
static constexpr auto ExtensionPermitPty = "permit-pty";
static constexpr auto ExtensionPermitUserRc = "permit-user-rc";

class SSHKey {
public:
  SSHKey() = default;
  SSHKey(const SSHKey&) = delete;
  SSHKey(SSHKey&&) = default;
  SSHKey& operator=(const SSHKey&) = delete;
  SSHKey& operator=(SSHKey&&) = default;

  explicit SSHKey(sshkey* key);

  static absl::StatusOr<SSHKey> fromPrivateKeyFile(const std::string& filepath);
  static absl::StatusOr<SSHKey> fromPublicKeyFile(const std::string& filepath);
  static absl::StatusOr<SSHKey> fromBlob(const bytes& public_key);
  static absl::StatusOr<SSHKey> generate(sshkey_types type, uint32_t bits);

  bool operator==(const SSHKey& other) const;
  bool operator!=(const SSHKey& other) const;

  absl::StatusOr<std::string> fingerprint(sshkey_fp_rep representation = SSH_FP_DEFAULT) const;
  std::string name() const;
  sshkey_types keyType() const;

  // Returns the cert-less equivalent to a certified key type
  sshkey_types keyTypePlain() const;

  absl::Status convertToSignedUserCertificate(
    uint64_t serial,
    string_list principals,
    string_list extensions,
    absl::Duration valid_duration,
    const SSHKey& signer);

  absl::StatusOr<bytes> toBlob() const;
  absl::StatusOr<bytes> sign(bytes_view payload) const;
  absl::Status verify(bytes_view signature, bytes_view payload);

private:
  SshKeyPtr key_;
};
} // namespace openssh