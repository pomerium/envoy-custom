#include "source/extensions/filters/network/ssh/openssh.h"

#include "absl/time/time.h"
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
    return absl::InvalidArgumentError("sshkey_fingerprint_raw failed");
  }
  return std::string{fp.get()};
}

std::string_view SSHKey::name() const {
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
                                signer.namePtr(), nullptr, nullptr);
      err != 0) {
    return statusFromErr(err);
  }
  return absl::OkStatus();
}

absl::StatusOr<bytes> SSHKey::toPublicKeyBlob() const {
  CBytesPtr buf;
  size_t len = 0;
  if (auto err = sshkey_to_blob(key_.get(), std::out_ptr(buf), &len); err != 0) {
    return statusFromErr(err);
  }
  return to_bytes(unsafe_forge_span(buf.get(), len));
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

  if (auto err = sshkey_from_private(key_.get(), std::out_ptr(pub)); err != 0) {
    return statusFromErr(err);
  }
  if (auto err = sshkey_format_text(pub.get(), buf.get()); err != 0) {
    return statusFromErr(err);
  }
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

sshkey_types SSHKey::keyTypeFromName(const std::string& name) {
  return static_cast<sshkey_types>(sshkey_type_from_name(name.c_str()));
}

absl::StatusOr<std::vector<openssh::SSHKeyPtr>> loadHostKeysFromConfig(
  const pomerium::extensions::ssh::CodecConfig& config) {
  auto hostKeys = config.host_keys();
  std::vector<openssh::SSHKeyPtr> out;
  for (const auto& hostKey : hostKeys) {
    auto key = openssh::SSHKey::fromPrivateKeyFile(hostKey);
    if (!key.ok()) {
      return key.status();
    }
    out.push_back(std::move(*key));
  }
  return out;
}

// SSHCipher

SSHCipher::SSHCipher(const std::string& cipher_name,
                     bytes iv, bytes key,
                     CipherMode mode) {
  auto cipher = cipher_by_name(cipher_name.c_str());
  if (cipher == nullptr) {
    PANIC(fmt::format("unknown cipher: {}", cipher_name));
  }
  block_size_ = cipher_blocksize(cipher);
  auth_len_ = cipher_authlen(cipher);
  iv_len_ = cipher_ivlen(cipher);
  aad_len_ = (auth_len_ != 0) ? static_cast<uint32_t>(sizeof(seqnum_t)) : 0;

  auto err = cipher_init(std::out_ptr(ctx_), cipher, key.data(), static_cast<uint32_t>(key.size()),
                         iv.data(), static_cast<uint32_t>(iv.size()), std::to_underlying(mode));
  if (err != 0) {
    PANIC(fmt::format("cipher_init failed: {}", ssh_err(err)));
  }
}

absl::StatusOr<size_t> SSHCipher::encryptPacket(seqnum_t seqnum,
                                                Envoy::Buffer::Instance& out,
                                                Envoy::Buffer::Instance& in) {
  auto in_length = in.length();
  auto in_data = in.linearize(static_cast<uint32_t>(in_length));
  uint32_t packlen = static_cast<uint32_t>(in_length);
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
  return out_len;
}

absl::StatusOr<size_t> SSHCipher::decryptPacket(seqnum_t seqnum,
                                                Envoy::Buffer::Instance& out,
                                                Envoy::Buffer::Instance& in,
                                                uint32_t packet_length) {
  size_t need = packet_length + aad_len_ + auth_len_;
  if (in.length() < need) {
    return 0; // incomplete packet
  }

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
  in.drain(need);
  out_data.commit(out_data.length());
  return need;
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
} // namespace openssh