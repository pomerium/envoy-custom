#pragma once

#include <cstdint> // IWYU pragma: keep
#include <cstdio>  // IWYU pragma: keep

#include "source/common/common/c_smart_ptr.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "absl/time/time.h"

extern "C" {
#include "openssh/ssh2.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/cipher.h"
#include "openssh/ssherr.h"
#include "openssh/authfile.h"
#include "openssh/digest.h"
}

namespace openssh {

using SshKeyPtr = Envoy::CSmartPtr<sshkey, sshkey_free>;
using SshBufPtr = Envoy::CSmartPtr<sshbuf, sshbuf_free>;
using SshCipherCtxPtr = Envoy::CSmartPtr<sshcipher_ctx, cipher_free>;

inline absl::StatusCode statusCodeFromErr(int n) {
  switch (n) {
  case SSH_ERR_SUCCESS:                   return absl::StatusCode::kOk;
  case SSH_ERR_INTERNAL_ERROR:            return absl::StatusCode::kInternal;
  case SSH_ERR_ALLOC_FAIL:                return absl::StatusCode::kResourceExhausted;
  case SSH_ERR_MESSAGE_INCOMPLETE:        return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_INVALID_FORMAT:            return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_BIGNUM_IS_NEGATIVE:        return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_STRING_TOO_LARGE:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_BIGNUM_TOO_LARGE:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_ECPOINT_TOO_LARGE:         return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_NO_BUFFER_SPACE:           return absl::StatusCode::kInternal;
  case SSH_ERR_INVALID_ARGUMENT:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_BITS_MISMATCH:         return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_EC_CURVE_INVALID:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_TYPE_MISMATCH:         return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_TYPE_UNKNOWN:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_EC_CURVE_MISMATCH:         return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_EXPECTED_CERT:             return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_LACKS_CERTBLOB:        return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:     return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY: return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_INVALID_EC_VALUE:      return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_SIGNATURE_INVALID:         return absl::StatusCode::kPermissionDenied;
  case SSH_ERR_LIBCRYPTO_ERROR:           return absl::StatusCode::kInternal;
  case SSH_ERR_UNEXPECTED_TRAILING_DATA:  return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_SYSTEM_ERROR:              return absl::StatusCode::kInternal;
  case SSH_ERR_KEY_CERT_INVALID:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_AGENT_COMMUNICATION:       return absl::StatusCode::kUnavailable;
  case SSH_ERR_AGENT_FAILURE:             return absl::StatusCode::kUnavailable;
  case SSH_ERR_DH_GEX_OUT_OF_RANGE:       return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_DISCONNECTED:              return absl::StatusCode::kCancelled;
  case SSH_ERR_MAC_INVALID:               return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_NO_CIPHER_ALG_MATCH:       return absl::StatusCode::kUnimplemented;
  case SSH_ERR_NO_MAC_ALG_MATCH:          return absl::StatusCode::kUnimplemented;
  case SSH_ERR_NO_COMPRESS_ALG_MATCH:     return absl::StatusCode::kUnimplemented;
  case SSH_ERR_NO_KEX_ALG_MATCH:          return absl::StatusCode::kUnimplemented;
  case SSH_ERR_NO_HOSTKEY_ALG_MATCH:      return absl::StatusCode::kUnimplemented;
  case SSH_ERR_NO_HOSTKEY_LOADED:         return absl::StatusCode::kInternal;
  case SSH_ERR_PROTOCOL_MISMATCH:         return absl::StatusCode::kUnimplemented;
  case SSH_ERR_NO_PROTOCOL_VERSION:       return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_NEED_REKEY:                return absl::StatusCode::kFailedPrecondition;
  case SSH_ERR_PASSPHRASE_TOO_SHORT:      return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_FILE_CHANGED:              return absl::StatusCode::kAborted;
  case SSH_ERR_KEY_UNKNOWN_CIPHER:        return absl::StatusCode::kUnimplemented;
  case SSH_ERR_KEY_WRONG_PASSPHRASE:      return absl::StatusCode::kPermissionDenied;
  case SSH_ERR_KEY_BAD_PERMISSIONS:       return absl::StatusCode::kPermissionDenied;
  case SSH_ERR_KEY_CERT_MISMATCH:         return absl::StatusCode::kPermissionDenied;
  case SSH_ERR_KEY_NOT_FOUND:             return absl::StatusCode::kNotFound;
  case SSH_ERR_AGENT_NOT_PRESENT:         return absl::StatusCode::kAborted;
  case SSH_ERR_AGENT_NO_IDENTITIES:       return absl::StatusCode::kAborted;
  case SSH_ERR_BUFFER_READ_ONLY:          return absl::StatusCode::kInternal;
  case SSH_ERR_KRL_BAD_MAGIC:             return absl::StatusCode::kInternal;
  case SSH_ERR_KEY_REVOKED:               return absl::StatusCode::kPermissionDenied;
  case SSH_ERR_CONN_CLOSED:               return absl::StatusCode::kCancelled;
  case SSH_ERR_CONN_TIMEOUT:              return absl::StatusCode::kDeadlineExceeded;
  case SSH_ERR_CONN_CORRUPT:              return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_PROTOCOL_ERROR:            return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_KEY_LENGTH:                return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_NUMBER_TOO_LARGE:          return absl::StatusCode::kInvalidArgument;
  case SSH_ERR_SIGN_ALG_UNSUPPORTED:      return absl::StatusCode::kUnimplemented;
  case SSH_ERR_FEATURE_UNSUPPORTED:       return absl::StatusCode::kUnimplemented;
  case SSH_ERR_DEVICE_NOT_FOUND:          return absl::StatusCode::kNotFound;
  }
  return absl::StatusCode::kUnknown;
}

inline absl::Status statusFromErr(int n) {
  return {statusCodeFromErr(n), ssh_err(n)};
}

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

  explicit SSHKey(sshkey* key)
      : key_(key) {}

  static absl::StatusOr<SSHKey> fromPrivateKeyFile(const std::string& filepath) {
    sshkey* key;
    auto err = sshkey_load_private(filepath.c_str(), nullptr, &key, nullptr);
    if (err != 0) {
      return statusFromErr(err);
    }
    return SSHKey(key);
  }

  static absl::StatusOr<SSHKey> fromPublicKeyFile(const std::string& filepath) {
    sshkey* key;
    auto err = sshkey_load_public(filepath.c_str(), &key, nullptr);
    if (err != 0) {
      return statusFromErr(err);
    }
    return SSHKey(key);
  }

  static absl::StatusOr<SSHKey> fromBlob(const bytes& public_key) {
    sshkey* key;
    if (auto err = sshkey_from_blob(public_key.data(), public_key.size(), &key); err != 0) {
      return statusFromErr(err);
    }
    return SSHKey(key);
  }

  static absl::StatusOr<SSHKey> generate(sshkey_types type, uint32_t bits) {
    sshkey* key;
    if (auto err = sshkey_generate(type, bits, &key); err != 0) {
      return statusFromErr(err);
    }
    return SSHKey(key);
  }

  bool operator==(const SSHKey& other) const {
    return sshkey_equal(key_.get(), other.key_.get()) == 1;
  }

  bool operator!=(const SSHKey& other) const {
    return !this->operator==(other);
  }

  absl::StatusOr<std::string> fingerprint(sshkey_fp_rep representation = SSH_FP_DEFAULT) const {
    // TODO: make the hash algorithm configurable?
    char* fp = sshkey_fingerprint(key_.get(), SSH_FP_HASH_DEFAULT, representation);
    if (fp == nullptr) {
      return absl::InvalidArgumentError("sshkey_fingerprint_raw failed");
    }
    return std::string(fp);
  }

  std::string name() const {
    return sshkey_ssh_name(key_.get());
  }

  // Returns the key type
  sshkey_types keyType() const {
    return static_cast<sshkey_types>(key_->type);
  }

  // Returns the cert-less equivalent to a certified key type
  sshkey_types keyTypePlain() const {
    return static_cast<sshkey_types>(sshkey_type_plain(key_->type));
  }

  absl::Status convertToSignedUserCertificate(
    uint64_t serial,
    string_list principals,
    string_list extensions,
    absl::Duration valid_duration,
    const SSHKey& signer) {
    if (auto err = sshkey_to_certified(key_.get()); err != 0) {
      return statusFromErr(err);
    }
    key_->cert->type = SSH2_CERT_TYPE_USER;
    key_->cert->serial = serial;
    key_->cert->nprincipals = static_cast<uint32_t>(principals.size());
    char** principals_arr = new char*[principals.size()];
    for (size_t i = 0; i < principals.size(); i++) {
      principals_arr[i] = strdup(principals[i].c_str());
    }
    key_->cert->principals = principals_arr;
    key_->cert->extensions = sshbuf_new();
    std::sort(extensions.begin(), extensions.end());
    for (const auto& ext : extensions) {
      sshbuf_put_cstring(key_->cert->extensions, ext.c_str());
      sshbuf_put_string(key_->cert->extensions, nullptr, 0);
    }

    key_->cert->valid_after = absl::ToUnixSeconds(absl::Now());
    key_->cert->valid_before = absl::ToUnixSeconds(absl::Now() + valid_duration);

    if (auto err = sshkey_from_private(signer.key_.get(),
                                       &key_->cert->signature_key);
        err != 0) {
      return statusFromErr(err);
    }
    if (auto err = sshkey_certify(key_.get(), signer.key_.get(),
                                  signer.name().data(), nullptr, nullptr);
        err != 0) {
      return statusFromErr(err);
    }
    return absl::OkStatus();
  }

  absl::StatusOr<bytes> toBlob() const {
    uint8_t* buf;
    size_t len;
    if (auto err = sshkey_to_blob(key_.get(), &buf, &len); err != 0) {
      return statusFromErr(err);
    }
    return bytes{buf, buf + len};
  }

  absl::StatusOr<bytes> sign(bytes_view<> payload) const {
    uint8_t* sig;
    size_t len;
    auto err = sshkey_sign(key_.get(), &sig, &len, payload.data(), payload.size(),
                           nullptr, nullptr, nullptr, 0);
    if (err != 0) {
      return statusFromErr(err);
    }
    return bytes{sig, sig + len};
  }

  absl::Status verify(bytes_view<> signature, bytes_view<> payload) {
    auto err = sshkey_verify(key_.get(),
                             signature.data(), signature.size(),
                             payload.data(), payload.size(),
                             name().data(),
                             0, nullptr);
    if (err != 0) {
      return statusFromErr(err);
    }
    return absl::OkStatus();
  }

private:
  SshKeyPtr key_;
};
} // namespace openssh