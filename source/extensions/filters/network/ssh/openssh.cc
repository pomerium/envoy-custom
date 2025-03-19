#include "source/extensions/filters/network/ssh/openssh.h"

#include "absl/time/time.h"

extern "C" {
#include "openssh/ssh2.h"
#include "openssh/authfile.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
}

namespace openssh {

absl::StatusCode statusCodeFromErr(int n) {
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

absl::Status statusFromErr(int n) {
  return {statusCodeFromErr(n), ssh_err(n)};
}

SSHKey::SSHKey(sshkey* key)
    : key_(key) {}

absl::StatusOr<SSHKey> SSHKey::fromPrivateKeyFile(const std::string& filepath) {
  sshkey* key = nullptr;
  auto err = sshkey_load_private(filepath.c_str(), nullptr, &key, nullptr);
  if (err != 0) {
    return statusFromErr(err);
  }
  return SSHKey(key);
}

absl::StatusOr<SSHKey> SSHKey::fromPublicKeyFile(const std::string& filepath) {
  sshkey* key = nullptr;
  auto err = sshkey_load_public(filepath.c_str(), &key, nullptr);
  if (err != 0) {
    return statusFromErr(err);
  }
  return SSHKey(key);
}

absl::StatusOr<SSHKey> SSHKey::fromBlob(const bytes& public_key) {
  sshkey* key = nullptr;
  if (auto err = sshkey_from_blob(public_key.data(), public_key.size(), &key); err != 0) {
    return statusFromErr(err);
  }
  return SSHKey(key);
}

absl::StatusOr<SSHKey> SSHKey::generate(sshkey_types type, uint32_t bits) {
  sshkey* key = nullptr;
  if (auto err = sshkey_generate(type, bits, &key); err != 0) {
    return statusFromErr(err);
  }
  return SSHKey(key);
}

bool SSHKey::operator==(const SSHKey& other) const {
  return sshkey_equal(key_.get(), other.key_.get()) == 1;
}

bool SSHKey::operator!=(const SSHKey& other) const {
  return !this->operator==(other);
}

absl::StatusOr<std::string> SSHKey::fingerprint(sshkey_fp_rep representation) const {
  // TODO: make the hash algorithm configurable?
  char* fp = sshkey_fingerprint(key_.get(), SSH_DIGEST_SHA256, representation);
  if (fp == nullptr) {
    return absl::InvalidArgumentError("sshkey_fingerprint_raw failed");
  }
  return std::string(fp);
}

std::string SSHKey::name() const {
  return sshkey_ssh_name(key_.get());
}

sshkey_types SSHKey::keyType() const {
  return static_cast<sshkey_types>(key_->type);
}

sshkey_types SSHKey::keyTypePlain() const {
  return static_cast<sshkey_types>(sshkey_type_plain(key_->type));
}

absl::Status SSHKey::convertToSignedUserCertificate(
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
  auto principals_arr = std::make_unique<char*[]>(principals.size());
  for (size_t i = 0; i < principals.size(); i++) {
    principals_arr[i] = strdup(principals[i].c_str());
  }
  key_->cert->principals = principals_arr.release();
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

absl::StatusOr<bytes> SSHKey::toBlob() const {
  uint8_t* buf = nullptr;
  size_t len = 0;
  if (auto err = sshkey_to_blob(key_.get(), &buf, &len); err != 0) {
    return statusFromErr(err);
  }
  return to_bytes(unsafe_forge_span(buf, len));
}

absl::StatusOr<bytes> SSHKey::sign(bytes_view payload) const {
  uint8_t* sig = nullptr;
  size_t len = 0;
  auto err = sshkey_sign(key_.get(), &sig, &len, payload.data(), payload.size(),
                         nullptr, nullptr, nullptr, 0);
  if (err != 0) {
    return statusFromErr(err);
  }
  return to_bytes(unsafe_forge_span(sig, len));
}

absl::Status SSHKey::verify(bytes_view signature, bytes_view payload) {
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

} // namespace openssh