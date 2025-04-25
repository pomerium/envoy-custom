#pragma once

#include <cstdint> // IWYU pragma: keep
#include <cstdio>  // IWYU pragma: keep

#include "source/common/common/c_smart_ptr.h"

#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/cipher.h"
}

namespace openssh {

namespace detail {
using sshkey_ptr = Envoy::CSmartPtr<sshkey, sshkey_free>;
using sshcipher_ctx_ptr = Envoy::CSmartPtr<sshcipher_ctx, cipher_free>;
} // namespace detail

template <typename T = char>
using CStringPtr = std::unique_ptr<T, decltype([](void* p) { ::free(p); })>;
using CBytesPtr = CStringPtr<uint8_t>;

absl::StatusCode statusCodeFromErr(int n);
absl::Status statusFromErr(int n);

static constexpr auto ExtensionNoTouchRequired = "no-touch-required";
static constexpr auto ExtensionPermitX11Forwarding = "permit-X11-forwarding";
static constexpr auto ExtensionPermitPortForwarding = "permit-port-forwarding";
static constexpr auto ExtensionPermitPty = "permit-pty";
static constexpr auto ExtensionPermitUserRc = "permit-user-rc";

class SSHKey {
public:
  SSHKey(const SSHKey&) = delete;
  SSHKey(SSHKey&&) = default;
  SSHKey& operator=(const SSHKey&) = delete;
  SSHKey& operator=(SSHKey&&) = default;

  bool operator==(const SSHKey& other) const;
  bool operator!=(const SSHKey& other) const;

  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPrivateKeyFile(const std::string& filepath);
  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPublicKeyBlob(const bytes& public_key);
  static absl::StatusOr<std::unique_ptr<SSHKey>> generate(sshkey_types type, uint32_t bits);

  static sshkey_types keyTypeFromName(const std::string& name);

  absl::StatusOr<std::string> fingerprint(sshkey_fp_rep representation = SSH_FP_DEFAULT) const;
  std::string_view name() const;
  sshkey_types keyType() const;

  // Returns the cert-less equivalent to a certified key type
  sshkey_types keyTypePlain() const;

  absl::Status convertToSignedUserCertificate(
    uint64_t serial,
    string_list principals,
    string_list extensions,
    absl::Duration valid_duration,
    const SSHKey& signer);

  absl::StatusOr<bytes> toPublicKeyBlob() const;
  absl::StatusOr<std::string> toPrivateKeyPem() const;
  absl::StatusOr<std::string> toPublicKeyPem() const;
  absl::StatusOr<bytes> sign(bytes_view payload) const;
  absl::Status verify(bytes_view signature, bytes_view payload);

private:
  explicit SSHKey(detail::sshkey_ptr key);

  const char* namePtr() const;

  detail::sshkey_ptr key_;
};

using SSHKeyPtr = std::unique_ptr<SSHKey>;

absl::StatusOr<std::vector<openssh::SSHKeyPtr>> loadHostKeysFromConfig(
  const pomerium::extensions::ssh::CodecConfig& config);

enum class CipherMode : int {
  Read = CIPHER_DECRYPT,
  Write = CIPHER_ENCRYPT,
};

class SSHCipher {
public:
  SSHCipher(const std::string& cipher_name,
            bytes iv, bytes key,
            CipherMode mode);
  absl::StatusOr<size_t> encryptPacket(seqnum_t seqnum,
                                       Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in);

  absl::StatusOr<size_t> decryptPacket(seqnum_t seqnum,
                                       Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in,
                                       uint32_t packet_length);

  absl::StatusOr<uint32_t> packetLength(seqnum_t seqnum,
                                        const Envoy::Buffer::Instance& in);

  inline size_t blockSize() const { return block_size_; }
  inline size_t authLen() const { return auth_len_; }
  inline size_t ivLen() const { return iv_len_; }
  inline size_t aadLen() const { return aad_len_; }

private:
  detail::sshcipher_ctx_ptr ctx_;
  uint32_t block_size_;
  uint32_t auth_len_;
  uint32_t iv_len_;
  uint32_t aad_len_;
};

} // namespace openssh