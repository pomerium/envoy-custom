#include "source/extensions/filters/network/ssh/openssh.h"

#include "absl/time/time.h"
#include "source/common/span.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/common/common/assert.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

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
    outSpan[i] = ::strdup(input[i].c_str());
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

std::string statusMessageFromErr(int n) {
  return ssh_err(n);
}

absl::Status statusFromErr(int n) {
  return {statusCodeFromErr(n), statusMessageFromErr(n)};
}

SSHKey::SSHKey(detail::sshkey_ptr key)
    : key_(std::move(key)) {}

absl::StatusOr<SSHKeyPtr> SSHKey::fromPrivateKeyFile(const std::string& filepath) {
  detail::sshkey_ptr key;
  auto err = sshkey_load_private(filepath.c_str(), nullptr, std::out_ptr(key), nullptr);
  if (err != 0) {
    return statusFromErr(err);
  }
  return std::unique_ptr<SSHKey>(new SSHKey(std::move(key)));
}

absl::StatusOr<SSHKeyPtr> SSHKey::fromPrivateKeyFile(Envoy::Filesystem::Instance& fs, const std::string& filepath) {
  auto data = fs.fileReadToEnd(filepath);
  if (!data.ok()) {
    return data.status();
  }
  detail::sshkey_ptr key;
  detail::sshbuf_ptr tmp_buf = sshbuf_from(data->data(), data->size());
  auto err = sshkey_parse_private_fileblob_type(tmp_buf.get(), KEY_UNSPEC, nullptr, std::out_ptr(key), nullptr);
  if (err != 0) {
    return statusFromErr(err);
  }
  return std::unique_ptr<SSHKey>(new SSHKey(std::move(key)));
}

absl::StatusOr<SSHKeyPtr> SSHKey::fromPublicKeyBlob(const bytes& public_key) {
  detail::sshkey_ptr key;
  if (auto err = sshkey_from_blob(public_key.data(), public_key.size(), std::out_ptr(key)); err != 0) {
    return statusFromErr(err);
  }
  return std::unique_ptr<SSHKey>(new SSHKey(std::move(key)));
}

absl::StatusOr<SSHKeyPtr> SSHKey::generate(sshkey_types type, uint32_t bits) {
  detail::sshkey_ptr key;
  if (auto err = sshkey_generate(type, bits, std::out_ptr(key)); err != 0) {
    return statusFromErr(err);
  }
  return std::unique_ptr<SSHKey>(new SSHKey(std::move(key)));
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
  absl::Duration valid_duration,
  const SSHKey& signer) {
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
  key_->cert->extensions = sshbuf_new();
  std::sort(extensions.begin(), extensions.end());
  for (const auto& ext : extensions) {
    sshbuf_put_cstring(key_->cert->extensions, ext.c_str());
    sshbuf_put_string(key_->cert->extensions, nullptr, 0);
  }

  key_->cert->valid_after = absl::ToUnixSeconds(absl::Now());
  key_->cert->valid_before = absl::ToUnixSeconds(absl::Now() + valid_duration);

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

absl::StatusOr<bytes> SSHKey::toPublicKeyBlob() const {
  CBytesPtr buf;
  size_t len = 0;
  // only fails on OOM or if the key is in an invalid state
  auto r = sshkey_to_blob(key_.get(), std::out_ptr(buf), &len);
  RELEASE_ASSERT(r == 0, "sshkey_to_blob failed");
  return to_bytes(unsafe_forge_span(buf.get(), len));
}

absl::StatusOr<std::unique_ptr<SSHKey>> SSHKey::toPublicKey() const {
  detail::sshkey_ptr key;
  // only fails on OOM or if the key is in an invalid state
  auto r = sshkey_from_private(key_.get(), std::out_ptr(key));
  RELEASE_ASSERT(r == 0, "sshkey_from_private failed");
  return std::unique_ptr<SSHKey>(new SSHKey(std::move(key)));
}

absl::StatusOr<std::string> SSHKey::toPrivateKeyPem() const {
  detail::sshbuf_ptr buf(sshbuf_new());
  if (auto err = sshkey_private_to_fileblob(
        key_.get(), buf.get(), "", "", SSHKEY_PRIVATE_PEM, nullptr, 0);
      err != 0) {
    return statusFromErr(err);
  }
  auto view = unsafe_forge_span(sshbuf_ptr(buf.get()), sshbuf_len(buf.get()));
  return std::string(view.begin(), view.end());
}

absl::StatusOr<std::string> SSHKey::toPublicKeyPem() const {
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

absl::StatusOr<bytes> SSHKey::sign(bytes_view payload) const {
  CBytesPtr sig;
  size_t len = 0;
  auto err = sshkey_sign(key_.get(), std::out_ptr(sig), &len, payload.data(), payload.size(),
                         nullptr, nullptr, nullptr, 0);
  if (err != 0) {
    return statusFromErr(err);
  }
  return to_bytes(unsafe_forge_span(sig.get(), len));
}

absl::Status SSHKey::verify(bytes_view signature, bytes_view payload) {
  auto err = sshkey_verify(key_.get(),
                           signature.data(), signature.size(),
                           payload.data(), payload.size(),
                           namePtr(),
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

// SSHCipher

SSHCipher::SSHCipher(const std::string& cipher_name,
                     const iv_bytes& iv,
                     const key_bytes& key,
                     CipherMode mode,
                     uint32_t aad_len)
    : name_(cipher_name) {
  auto cipher = cipher_by_name(cipher_name.c_str());
  if (cipher == nullptr) {
    PANIC(fmt::format("unknown cipher: {}", cipher_name));
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
    PANIC(fmt::format("failed to initialize cipher: {}", ssh_err(err)));
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
    return absl::AbortedError(fmt::format("encrypt failed: {}", ssh_err(r)));
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
    return absl::AbortedError(fmt::format("decrypt failed: {}", ssh_err(r)));
  }
  in.drain(static_cast<uint64_t>(need));
  out_data.commit(out_data.length());
  return absl::OkStatus();
}

absl::StatusOr<uint32_t> SSHCipher::packetLength(seqnum_t seqnum,
                                                 const Envoy::Buffer::Instance& in) {
  uint32_t packlen = 0;
  std::array<uint8_t, 4> packet_header{};
  in.copyOut(0, 4, &packet_header);
  auto err = cipher_get_length(ctx_.get(), &packlen, seqnum,
                               packet_header.data(), packet_header.size());
  if (err != 0) {
    return absl::InvalidArgumentError("packet too small");
  }
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
    return absl::AbortedError(fmt::format("bad packet length: {} (seqnr {})", packlen, seqnum));
  }
  if (packlen % block_size_ != 0) {
    return absl::AbortedError(fmt::format("padding error: need {} block {} mod {}", packlen,
                                          block_size_, packlen % block_size_));
  }
  return packlen;
}

SSHMac::SSHMac(const std::string& mac_name, const key_bytes& key) {
  auto r = mac_setup(&mac_, const_cast<char*>(mac_name.c_str())); // NOLINT
  if (r != 0) {
    PANIC(fmt::format("unknown mac: {}", mac_name));
  }
  key_ = key;
  mac_.key = key_.data();
  r = mac_init(&mac_);
  if (r != 0) {
    PANIC(fmt::format("error initializing mac: {}", statusFromErr(r)));
  }
}
SSHMac::~SSHMac() {
  mac_clear(&mac_);
}
absl::StatusOr<size_t> SSHMac::compute(seqnum_t seqnum,
                                       Envoy::Buffer::Instance& out,
                                       const bytes_view& in) {
  auto res = out.reserveSingleSlice(mac_.mac_len);
  auto r = mac_compute(&mac_,
                       seqnum,
                       in.data(),
                       static_cast<int>(in.size()), // weird
                       static_cast<uint8_t*>(res.slice().mem_),
                       res.slice().len_);
  if (r != 0) {
    return statusFromErr(r);
  }
  auto len = res.length();
  res.commit(len);
  return static_cast<size_t>(len);
}
absl::Status SSHMac::verify(seqnum_t seqnum,
                            const bytes_view& data,
                            const bytes_view& mac) {
  if (mac_.mac_len > mac.size()) {
    return absl::InvalidArgumentError("invalid mac length");
  }
  auto r = mac_check(&mac_, seqnum, data.data(), data.size(), mac.data(), mac.size());
  if (r != 0) {
    return statusFromErr(r);
  }
  return absl::OkStatus();
}

} // namespace openssh