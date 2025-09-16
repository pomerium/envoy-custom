#include "source/extensions/filters/network/ssh/openssh.h"

#include "absl/time/time.h"
#include "source/common/span.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/common/common/assert.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/config/core/v3/base.pb.h"
#pragma clang unsafe_buffer_usage end

extern "C" {
#include "openssh/ssh2.h"
#include "openssh/authfile.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/sshbuf.h"
}

namespace openssh {

namespace detail {
using sshbuf_ptr = Envoy::CSmartPtr<sshbuf, sshbuf_free>;
} // namespace detail

namespace interop {
char** cloneStringListForC(const std::vector<std::string>& input) {
  char** out = static_cast<char**>(::calloc(input.size() + 1, sizeof(char*)));
  auto outSpan = unsafe_forge_span(out, input.size() + 1);
  for (size_t i = 0; i < input.size(); i++) {
#pragma clang unsafe_buffer_usage begin
    outSpan[i] = ::strdup(input[i].c_str());
#pragma clang unsafe_buffer_usage end
  }
  outSpan.back() = nullptr;
  return out;
}
} // namespace interop

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
  case SSH_ERR_KEY_BAD_PERMISSIONS:       return absl::StatusCode::kInvalidArgument;
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

std::string disconnectCodeToString(uint32_t n) {
  switch (n) {
  case SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:    return "host not allowed to connect";
  case SSH2_DISCONNECT_PROTOCOL_ERROR:                 return "protocol error";
  case SSH2_DISCONNECT_KEY_EXCHANGE_FAILED:            return "key exchange failed";
  case SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED:     return "host authentication failed";
  case SSH2_DISCONNECT_MAC_ERROR:                      return "mac error";
  case SSH2_DISCONNECT_COMPRESSION_ERROR:              return "compression error";
  case SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE:          return "service not available";
  case SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: return "protocol version not supported";
  case SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:        return "host key not verifiable";
  case SSH2_DISCONNECT_CONNECTION_LOST:                return "connection lost";
  case SSH2_DISCONNECT_BY_APPLICATION:                 return "by application";
  case SSH2_DISCONNECT_TOO_MANY_CONNECTIONS:           return "too many connections";
  case SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER:         return "auth cancelled by user";
  case SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: return "no more auth methods available";
  case SSH2_DISCONNECT_ILLEGAL_USER_NAME:              return "illegal user name";
  default:                                             return "(unknown)";
  }
}

uint32_t statusCodeToDisconnectCode(absl::StatusCode code) {
  switch (code) {
  case absl::StatusCode::kInvalidArgument:    return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kNotFound:           return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kAlreadyExists:      return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kPermissionDenied:   return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kFailedPrecondition: return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kAborted:            return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kOutOfRange:         return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kUnauthenticated:    return SSH2_DISCONNECT_PROTOCOL_ERROR;
  case absl::StatusCode::kResourceExhausted:  return SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE;
  case absl::StatusCode::kUnimplemented:      return SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE;
  case absl::StatusCode::kInternal:           return SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE;
  case absl::StatusCode::kUnavailable:        return SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE;
  case absl::StatusCode::kDataLoss:           return SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE;
  case absl::StatusCode::kCancelled:          return SSH2_DISCONNECT_BY_APPLICATION;
  case absl::StatusCode::kDeadlineExceeded:   return SSH2_DISCONNECT_BY_APPLICATION;
  default:                                    return SSH2_DISCONNECT_BY_APPLICATION;
  }
}
std::string statusMessageFromErr(int n) {
  return ssh_err(n);
}

absl::Status statusFromErr(int n) {
  return {statusCodeFromErr(n), statusMessageFromErr(n)};
}

SSHKey::SSHKey(detail::sshkey_ptr key, CStringPtr<char> comment)
    : key_(std::move(key)),
      comment_(std::move(comment)) {}

absl::StatusOr<SSHKeyPtr> SSHKey::fromPrivateKeyFile(const std::string& filepath) {
  detail::sshkey_ptr key;
  CStringPtr<char> comment;
  auto err = sshkey_load_private(filepath.c_str(), nullptr, std::out_ptr(key), std::out_ptr(comment));
  if (err != 0) {
    return statusFromErr(err);
  }
  return absl::WrapUnique(new SSHKey(std::move(key), std::move(comment)));
}

absl::StatusOr<std::unique_ptr<SSHKey>> SSHKey::fromPrivateKeyBytes(const std::string& bytes) {
  detail::sshbuf_ptr buffer{sshbuf_from(bytes.data(), bytes.size())};
  ASSERT(buffer != nullptr);
  detail::sshkey_ptr key;
  CStringPtr<char> comment;
  if (auto err = sshkey_parse_private_fileblob_type(
        buffer.get(), KEY_UNSPEC, nullptr, std::out_ptr(key), std::out_ptr(comment));
      err != 0) {
    return statusFromErr(err);
  }
  return absl::WrapUnique(new SSHKey(std::move(key), std::move(comment)));
}

absl::StatusOr<std::unique_ptr<SSHKey>> SSHKey::fromPrivateKeyDataSource(const ::corev3::DataSource& ds) {
  switch (ds.specifier_case()) {
  case corev3::DataSource::kFilename:
    if (auto r = SSHKey::fromPrivateKeyFile(ds.filename()); !r.ok()) {
      return statusf("failed to load ssh private key {}: {}", ds.filename(), r.status());
    } else {
      return r;
    }
  case corev3::DataSource::kInlineBytes:
    if (auto r = SSHKey::fromPrivateKeyBytes(ds.inline_bytes()); !r.ok()) {
      return statusf("failed to load ssh private key: {}", r.status());
    } else {
      return r;
    }
  case corev3::DataSource::kInlineString:
    if (auto r = SSHKey::fromPrivateKeyBytes(ds.inline_string()); !r.ok()) {
      return statusf("failed to load ssh private key: {}", r.status());
    } else {
      return r;
    }
  case corev3::DataSource::kEnvironmentVariable:
    return absl::UnimplementedError("environment variable data source not supported");
  default:
    return absl::InvalidArgumentError("data source is empty");
  }
}

absl::StatusOr<SSHKeyPtr> SSHKey::fromPublicKeyBlob(const bytes& public_key) {
  detail::sshkey_ptr key;
  if (auto err = sshkey_from_blob(public_key.data(), public_key.size(), std::out_ptr(key)); err != 0) {
    return statusFromErr(err);
  }
  return absl::WrapUnique(new SSHKey(std::move(key), nullptr));
}

absl::StatusOr<SSHKeyPtr> SSHKey::generate(sshkey_types type, uint32_t bits) {
  detail::sshkey_ptr key;
  if (auto err = sshkey_generate(type, bits, std::out_ptr(key)); err != 0) {
    return statusFromErr(err);
  }
  return absl::WrapUnique(new SSHKey(std::move(key), nullptr));
}

sshkey_types SSHKey::keyTypeFromName(const std::string& name) {
  return static_cast<sshkey_types>(sshkey_type_from_name(name.c_str()));
}

bool SSHKey::keyTypeIsCert(sshkey_types type) {
  return static_cast<bool>(sshkey_type_is_cert(type));
}

sshkey_types SSHKey::keyTypePlain(sshkey_types type) {
  return static_cast<sshkey_types>(sshkey_type_plain(type));
}

bool SSHKey::operator==(const SSHKey& other) const {
  return sshkey_equal(key_.get(), other.key_.get()) == 1;
}

bool SSHKey::operator!=(const SSHKey& other) const {
  return !this->operator==(other);
}

absl::StatusOr<std::string> SSHKey::fingerprint(sshkey_fp_rep representation) const {
  // TODO: make the hash algorithm configurable?
  CStringPtr fp{sshkey_fingerprint(key_.get(), SSH_DIGEST_SHA256, representation)};
  if (fp == nullptr) {
    return absl::InvalidArgumentError("sshkey_fingerprint failed");
  }
  return std::string{fp.get()};
}

bytes SSHKey::rawFingerprint() const {
  CBytesPtr fp_bytes;
  size_t fp_len{};
  auto r = sshkey_fingerprint_raw(key_.get(), SSH_DIGEST_SHA256, std::out_ptr(fp_bytes), &fp_len);
  ASSERT(r == 0); // only fails on invalid usage or oom
  return to_bytes(unsafe_forge_span(fp_bytes.get(), fp_len));
}

std::string_view SSHKey::keyTypeName() const {
  return {namePtr()};
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
  absl::Time valid_start_time,
  absl::Time valid_end_time,
  const SSHKey& signer) {
  if (valid_start_time >= valid_end_time) {
    return absl::InvalidArgumentError("valid_start_time >= valid_end_time");
  }
  if (auto err = sshkey_to_certified(key_.get()); err != 0) {
    return statusFromErr(err);
  }
  if (principals.size() > SSHKEY_CERT_MAX_PRINCIPALS) {
    return absl::InvalidArgumentError(fmt::format(
      "number of principals ({}) is more than the maximum allowed ({})",
      principals.size(), SSHKEY_CERT_MAX_PRINCIPALS));
  }
  key_->cert->type = SSH2_CERT_TYPE_USER;
  key_->cert->serial = serial;
  key_->cert->nprincipals = static_cast<uint32_t>(principals.size());
  key_->cert->principals = interop::cloneStringListForC(principals);
  ASSERT(key_->cert->extensions != nullptr);
  std::sort(extensions.begin(), extensions.end());
  for (const auto& ext : extensions) {
    sshbuf_put_cstring(key_->cert->extensions, ext.c_str());
    sshbuf_put_string(key_->cert->extensions, nullptr, 0);
  }

  key_->cert->valid_after = absl::ToUnixSeconds(valid_start_time);
  key_->cert->valid_before = absl::ToUnixSeconds(valid_end_time);

  // Despite the name of this function, the input can be a public key.
  //
  // This only fails on OOM or if we created an invalid cert that causes an error when it is copied;
  // the only practical way to do so would be creating a cert that has >256 principals, but we have
  // already checked for that case so it should not be possible.
  auto r = sshkey_from_private(signer.key_.get(), &key_->cert->signature_key);
  RELEASE_ASSERT(r == 0, "sshkey_from_private failed");

  const char* sig_alg = nullptr;
  if (signer.keyTypePlain() == KEY_RSA) {
    sig_alg = "rsa-sha2-512"; // force a stronger algorithm for rsa
  } else {
    sig_alg = signer.namePtr();
  }
  // NB: the signature algorithm argument to sshkey_certify only does anything for rsa keys, and
  // both the plain and cert names are accepted.
  if (auto err = sshkey_certify(key_.get(), signer.key_.get(),
                                sig_alg, nullptr, nullptr);
      err != 0) {
    return statusFromErr(err);
  }
  return absl::OkStatus();
}

bytes SSHKey::toPublicKeyBlob() const {
  CBytesPtr buf;
  size_t len = 0;
  // only fails on OOM or if the key is in an invalid state
  auto r = sshkey_to_blob(key_.get(), std::out_ptr(buf), &len);
  RELEASE_ASSERT(r == 0, "sshkey_to_blob failed");
  return to_bytes(unsafe_forge_span(buf.get(), len));
}

std::unique_ptr<SSHKey> SSHKey::toPublicKey() const {
  detail::sshkey_ptr key;
  // only fails on OOM or if the key is in an invalid state
  auto r = sshkey_from_private(key_.get(), std::out_ptr(key));
  RELEASE_ASSERT(r == 0, "sshkey_from_private failed");
  return absl::WrapUnique(new SSHKey(std::move(key), nullptr));
}

absl::StatusOr<std::string> SSHKey::formatPrivateKey(sshkey_private_format format) const {
  detail::sshbuf_ptr buf(sshbuf_new());
  const char* comment = "";
  if (comment_) {
    comment = comment_.get();
  }
  if (auto err = sshkey_private_to_fileblob(
        key_.get(), buf.get(), "", comment, format, nullptr, 0);
      err != 0) {
    return statusFromErr(err);
  }
  auto view = unsafe_forge_span(sshbuf_ptr(buf.get()), sshbuf_len(buf.get()));
  return std::string(view.begin(), view.end());
}

std::string SSHKey::formatPublicKey() const {
  detail::sshbuf_ptr buf(sshbuf_new());
  detail::sshkey_ptr pub;

  // only fails on OOM or if the key is in an invalid state
  auto r = sshkey_from_private(key_.get(), std::out_ptr(pub));
  RELEASE_ASSERT(r == 0, "sshkey_from_private failed");
  // only fails on OOM
  r = sshkey_format_text(pub.get(), buf.get());
  RELEASE_ASSERT(r == 0, "sshkey_format_text failed");
  auto view = unsafe_forge_span(sshbuf_ptr(buf.get()), sshbuf_len(buf.get()));
  return std::string(view.begin(), view.end());
}

absl::StatusOr<bytes> SSHKey::sign(bytes_view payload, std::string alg) const {
  CBytesPtr sig;
  size_t len = 0;
  const char* c_alg = nullptr;
  if (alg != "") {
    c_alg = alg.c_str();
  }
  auto err = sshkey_sign(key_.get(), std::out_ptr(sig), &len, payload.data(), payload.size(),
                         c_alg, nullptr, nullptr, 0);
  if (err != 0) {
    return statusFromErr(err);
  }
  return to_bytes(unsafe_forge_span(sig.get(), len));
}

absl::Status SSHKey::verify(bytes_view signature, bytes_view payload, std::string alg) {
  const char* c_alg = nullptr;
  if (alg != "") {
    c_alg = alg.c_str();
  }
  auto err = sshkey_verify(key_.get(),
                           signature.data(), signature.size(),
                           payload.data(), payload.size(),
                           c_alg,
                           0,        // bug compatibility
                           nullptr); // TODO: handle u2f signature info
  if (err != 0) {
    return statusFromErr(err);
  }
  return absl::OkStatus();
}

const char* SSHKey::namePtr() const {
  return sshkey_ssh_name(key_.get());
}

std::vector<std::string> SSHKey::signatureAlgorithmsForKeyType() const {
  // Regarding the rsa signature algorithms, openssh protocol extension doc states:
  //  These RSA/SHA-2 types should not appear in keys at rest or transmitted
  //  on the wire, but do appear in a SSH_MSG_KEXINIT's host-key algorithms
  //  field or in the "public key algorithm name" field of a "publickey"
  //  SSH_USERAUTH_REQUEST to indicate that the signature will use the
  //  specified algorithm.
  //
  // NB: sha1-variant rsa algorithms ("ssh-rsa"/"ssh-rsa-cert-v01@openssh.com") are not included.
  switch (keyType()) {
  case KEY_RSA:
    return {"rsa-sha2-256",
            "rsa-sha2-512"};
  case KEY_RSA_CERT:
    return {"rsa-sha2-256-cert-v01@openssh.com",
            "rsa-sha2-512-cert-v01@openssh.com"};
  default:
    return {std::string(keyTypeName())};
  }
}

std::optional<std::string> certSigningAlgorithmToPlain(const std::string& alg) {
  static const absl::flat_hash_map<const std::string, const std::string> names = {
    {"ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519"},
    {"sk-ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519@openssh.com"},
    {"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp256"},
    {"ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp384"},
    {"ecdsa-sha2-nistp521-cert-v01@openssh.com", "ecdsa-sha2-nistp521"},
    {"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"},
    {"rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-512"},
    {"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-256"},
  };
  auto n = names.find(alg);
  if (n != names.end()) {
    return n->second;
  }
  return std::nullopt;
}

// SSHCipher

SSHCipher::SSHCipher(const std::string& cipher_name,
                     const iv_bytes& iv,
                     const key_bytes& key,
                     CipherMode mode,
                     uint32_t aad_len)
    : name_(cipher_name) {
  auto cipher = cipher_by_name(cipher_name.c_str());
  if (cipher == nullptr) {
    throw Envoy::EnvoyException(fmt::format("unknown cipher: {}", cipher_name));
  }
  block_size_ = cipher_blocksize(cipher);
  auth_len_ = cipher_authlen(cipher);
  iv_len_ = cipher_ivlen(cipher);
  key_len_ = cipher_keylen(cipher);
  aad_len_ = aad_len;
  ASSERT(aad_len_ == 4);

  auto err = cipher_init(std::out_ptr(ctx_), cipher, key.data(), static_cast<uint32_t>(key.size()),
                         iv.data(), static_cast<uint32_t>(iv.size()), std::to_underlying(mode));
  if (err != 0) {
    throw Envoy::EnvoyException(fmt::format("failed to initialize cipher: {}", ssh_err(err)));
  }
}

absl::Status SSHCipher::encryptPacket(seqnum_t seqnum,
                                      Envoy::Buffer::Instance& out,
                                      Envoy::Buffer::Instance& in) {
  auto in_length = in.length();
  auto in_data = in.linearize(static_cast<uint32_t>(in_length));
  uint32_t packlen = static_cast<uint32_t>(in_length);
  ASSERT(packlen >= wire::MinPacketSize && packlen <= wire::MaxPacketSize);
  auto out_data = out.reserveSingleSlice(packlen + auth_len_);
  auto r = cipher_crypt(ctx_.get(), seqnum,
                        static_cast<uint8_t*>(out_data.slice().mem_),
                        static_cast<uint8_t*>(in_data),
                        static_cast<uint32_t>(packlen - aad_len_),
                        static_cast<uint32_t>(aad_len_),
                        static_cast<uint32_t>(auth_len_));
  if (r != 0) {
    return absl::InvalidArgumentError(fmt::format("encrypt failed: {}", ssh_err(r)));
  }
  in.drain(in_length);
  auto out_len = out_data.length();
  out_data.commit(out_len);
  return absl::OkStatus();
}

absl::Status SSHCipher::decryptPacket(seqnum_t seqnum,
                                      Envoy::Buffer::Instance& out,
                                      Envoy::Buffer::Instance& in,
                                      uint32_t packet_length) {
  size_t need = aad_len_ + packet_length + auth_len_;
  ASSERT(in.length() >= need);

  auto in_data = static_cast<uint8_t*>(in.linearize(static_cast<uint32_t>(need)));
  auto out_data = out.reserveSingleSlice(packet_length + aad_len_);
  auto r = cipher_crypt(ctx_.get(), seqnum,
                        static_cast<uint8_t*>(out_data.slice().mem_),
                        in_data,
                        packet_length,
                        aad_len_,
                        auth_len_);
  if (r != 0) {
    return absl::InvalidArgumentError(fmt::format("decrypt failed: {}", ssh_err(r)));
  }
  in.drain(static_cast<uint64_t>(need));
  out_data.commit(out_data.length());
  return absl::OkStatus();
}

absl::StatusOr<uint32_t> SSHCipher::packetLength(seqnum_t seqnum,
                                                 const Envoy::Buffer::Instance& in) {
  if (in.length() < wire::MinPacketSize) {
    return absl::InvalidArgumentError("packet too small");
  }
  uint32_t packlen = 0;
  std::array<uint8_t, 4> packet_header{};
  in.copyOut(0, 4, &packet_header);
  auto r = cipher_get_length(ctx_.get(), &packlen, seqnum, packet_header.data(), packet_header.size());
  ASSERT(r == 0); // cipher_get_length can only fail if packet_header.size() < 4
  if (packlen < wire::MinPacketSize || packlen > wire::MaxPacketSize) {
#ifdef SSH_DEBUG_SEQNUM
    for (auto test : std::vector<uint32_t>{sub_sat(seqnum, 1u), seqnum + 1, sub_sat(seqnum, 2u), seqnum + 2}) {
      if (cipher_get_length(ctx_.get(), &packlen, test, in_data, static_cast<uint32_t>(in_length)) == 0 &&
          packlen < wire::MaxPacketSize) {
        ENVOY_LOG(warn, "sequence number drift: packet decrypts with seqnr={}, but ours is {}",
                  test, seqnum);
      }
    }
#endif
    return absl::InvalidArgumentError(fmt::format("invalid decoded packet length: {} (seqnr {})", packlen, seqnum));
  }
  if (packlen % block_size_ != 0) {
    return absl::InvalidArgumentError(
      fmt::format("padding error: decoded packet length ({}) is not a multiple of the cipher block size ({})",
                  packlen, block_size_));
  }
  return packlen;
}

SSHMac::SSHMac(const std::string& mac_name, const key_bytes& key)
    : name_(mac_name),
      key_(key) {
  // The name and key fields of sshmac are only ever freed from kex_free_newkeys, which is never
  // called by us.
  // Note: c_str() returns const char*, and data() returns char*. For std::string specifically,
  // data() is guaranteed to be null-terminated.
  auto r = mac_setup(&mac_, name_.data());
  if (r != 0) {
    throw Envoy::EnvoyException(fmt::format("unknown mac: {}", mac_name));
  }
  mac_.key = key_.data();
  r = mac_init(&mac_);
  RELEASE_ASSERT(r == 0, fmt::format("error initializing mac: {}", statusFromErr(r)));
}

SSHMac::~SSHMac() {
  mac_clear(&mac_);
}

void SSHMac::compute(seqnum_t seqnum,
                     Envoy::Buffer::Instance& out,
                     const bytes_view& in) {
  ASSERT(!in.empty() && in.data() != nullptr);
  auto res = out.reserveSingleSlice(mac_.mac_len);
  // This accepts an int for the mac size parameter because HMAC_Update in OpenSSL 0.9.6 did, when
  // this function was originally written in 2001. HMAC_Update was changed to use size_t in 2004,
  // but mac_compute was never updated.
  auto r = mac_compute(&mac_,
                       seqnum,
                       in.data(), // can't be nullptr
                       static_cast<int>(in.size()),
                       static_cast<uint8_t*>(res.slice().mem_),
                       res.slice().len_);
  // this should only fail if we use it incorrectly
  RELEASE_ASSERT(r == 0, "mac_compute failed");
  res.commit(res.length());
}

absl::Status SSHMac::verify(seqnum_t seqnum,
                            const bytes_view& data,
                            const bytes_view& mac) {
  auto r = mac_check(&mac_, seqnum, data.data(), data.size(), mac.data(), mac.size());
  if (r != 0) {
    return statusFromErr(r);
  }
  return absl::OkStatus();
}

// Hash

Hash::Hash(int alg_id) {
  if (alg_id == -1) {
    // sentinel exception; see comment below
    throw Envoy::EnvoyException("invalid hash algorithm");
  }
  alg_ = alg_id;
  ctx_ = ssh_digest_start(alg_);
  if (ctx_ == nullptr) {
    throw Envoy::EnvoyException(fmt::format("invalid hash algorithm id: {}", alg_id));
  }
}

// This is a delegating constructor that invokes the constructor above after converting the alg
// name to the corresponding id. If the name is unknown, it returns -1. Iff the constructor above
// is passed an algorithm id of -1, it will throw an exception intended to be caught here, so that
// the original algorithm name can be logged in the assert. Otherwise, it would just error with
// "invalid hash algorithm id: -1" which is unhelpful.
//
// (see https://en.cppreference.com/w/cpp/language/constructor#Delegating_constructor and the
// example at the bottom of the page)
Hash::Hash(const std::string& alg_name) try
    : Hash(ssh_digest_alg_by_name(alg_name.c_str())) {
} catch (...) {
  throw Envoy::EnvoyException(fmt::format("invalid hash algorithm: {}", alg_name));
}

size_t Hash::size() const {
  return ssh_digest_bytes(alg_);
}

size_t Hash::blockSize() const {
  return ssh_digest_blocksize(ctx_.get());
}

void Hash::write(bytes_view data) {
  ssh_digest_update(ctx_.get(), data.data(), data.size());
}

void Hash::write(uint8_t data) {
  ssh_digest_update(ctx_.get(), &data, 1);
}

bytes Hash::sum() {
  bytes digest;
  digest.resize(size());
  ASSERT(digest.size() > 0 && digest.size() <= SSH_DIGEST_MAX_LENGTH);
  // this should only fail if we use it incorrectly, e.g. passing it an incorrect digest size
  auto r = ssh_digest_final(ctx_.get(), digest.data(), digest.size());
  RELEASE_ASSERT(r == 0, fmt::format("ssh_digest_final failed: {}", statusMessageFromErr(r)));
  return digest;
}

} // namespace openssh