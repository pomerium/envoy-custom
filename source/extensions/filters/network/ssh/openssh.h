#pragma once

#include <cstdint> // IWYU pragma: keep
#include <cstdio>  // IWYU pragma: keep

#include "source/common/common/c_smart_ptr.h"

#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "envoy/filesystem/filesystem.h"
#pragma clang unsafe_buffer_usage end

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/cipher.h"
#include "openssh/mac.h"
#include "openssh/digest.h"
}

namespace openssh {

namespace detail {
using sshkey_ptr = Envoy::CSmartPtr<sshkey, sshkey_free>;
using sshmac_ptr = Envoy::CSmartPtr<sshmac, mac_clear>;
using sshcipher_ctx_ptr = Envoy::CSmartPtr<sshcipher_ctx, cipher_free>;
using ssh_digest_ctx_ptr = Envoy::CSmartPtr<ssh_digest_ctx, ssh_digest_free>;
} // namespace detail

template <typename T = char>
using CStringPtr = std::unique_ptr<T, decltype([](void* p) { ::free(p); })>;
using CBytesPtr = CStringPtr<uint8_t>;
using iv_bytes = bytes;
using key_bytes = bytes;

absl::StatusCode statusCodeFromErr(int n);
absl::Status statusFromErr(int n);
std::string statusMessageFromErr(int n);

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

  // TOOD: remove this
  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPrivateKeyFile(Envoy::Filesystem::Instance& fs, const std::string& filepath);
  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPublicKeyBlob(const bytes& public_key);
  static absl::StatusOr<std::unique_ptr<SSHKey>> generate(sshkey_types type, uint32_t bits);

  static sshkey_types keyTypeFromName(const std::string& name);
  static bool keyTypeIsCert(sshkey_types type);
  // Returns the cert-less equivalent to a certified key type
  static sshkey_types keyTypePlain(sshkey_types type);

  absl::StatusOr<std::string> fingerprint(sshkey_fp_rep representation = SSH_FP_DEFAULT) const;
  std::string_view keyTypeName() const;
  sshkey_types keyType() const;
  sshkey_types keyTypePlain() const;
  std::vector<std::string> signatureAlgorithmsForKeyType() const;

  absl::Status convertToSignedUserCertificate(
    uint64_t serial,
    string_list principals,
    string_list extensions,
    absl::Duration valid_duration,
    const SSHKey& signer);

  absl::StatusOr<bytes> toPublicKeyBlob() const;
  absl::StatusOr<std::unique_ptr<SSHKey>> toPublicKey() const;
  absl::StatusOr<std::string> toPrivateKeyPem() const;
  absl::StatusOr<std::string> toPublicKeyPem() const;
  absl::StatusOr<bytes> sign(bytes_view payload) const;
  absl::Status verify(bytes_view signature, bytes_view payload);

  const struct sshkey* sshKeyForTest() const { return key_.get(); };

private:
  explicit SSHKey(detail::sshkey_ptr key);

  const char* namePtr() const;

  detail::sshkey_ptr key_;
};

using SSHKeyPtr = std::unique_ptr<SSHKey>;

absl::StatusOr<std::vector<openssh::SSHKeyPtr>> loadHostKeys(std::ranges::range auto const& filenames) {
  std::vector<openssh::SSHKeyPtr> out;
  std::unordered_map<sshkey_types, std::string> keyTypes;
  for (const auto& hostKey : filenames) {
    auto key = openssh::SSHKey::fromPrivateKeyFile(hostKey);
    if (!key.ok()) {
      return key.status();
    }
    if (auto keyType = (*key)->keyTypePlain(); keyTypes.contains(keyType)) {
      ENVOY_LOG_MISC(error, "note: keys with algorithm {}: {}, {}", (*key)->keyTypeName(),
                     keyTypes.at(keyType), hostKey);
      return absl::InvalidArgumentError("host keys must have unique algorithms");
    } else {
      keyTypes[keyType] = hostKey;
    }
    out.push_back(std::move(*key));
  }
  return out;
}

enum class CipherMode : int {
  Read = CIPHER_DECRYPT,
  Write = CIPHER_ENCRYPT,
};

class SSHCipher {
public:
  SSHCipher(const std::string& cipher_name,
            const iv_bytes& iv, const key_bytes& key,
            CipherMode mode, uint32_t aad_len);
  // Encrypts a packet (encoded by wire::encodePacket) contained in 'in' into 'out', draining the
  // bytes from 'in'.
  absl::Status encryptPacket(seqnum_t seqnum,
                             Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in);

  absl::Status decryptPacket(seqnum_t seqnum,
                             Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in,
                             uint32_t packet_length);

  absl::StatusOr<uint32_t> packetLength(seqnum_t seqnum, const Envoy::Buffer::Instance& in);

  inline size_t blockSize() const { return block_size_; }
  inline size_t authLen() const { return auth_len_; }
  inline size_t ivLen() const { return iv_len_; }
  inline size_t keyLen() const { return key_len_; }
  inline size_t aadLen() const { return aad_len_; }
  inline const std::string& name() const { return name_; }

private:
  detail::sshcipher_ctx_ptr ctx_;
  uint32_t block_size_;
  uint32_t auth_len_;
  uint32_t iv_len_;
  uint32_t key_len_;
  uint32_t aad_len_;
  std::string name_;
};

class SSHMac {
public:
  SSHMac(const std::string& mac_name, const key_bytes& key);
  ~SSHMac();

  absl::StatusOr<size_t> compute(seqnum_t seqnum,
                                 Envoy::Buffer::Instance& out,
                                 const bytes_view& in);
  absl::Status verify(seqnum_t seqnum,
                      const bytes_view& data,
                      const bytes_view& mac);

  inline size_t length() const { return mac_.mac_len; }
  inline bool isETM() const { return mac_.etm != 0; }

private:
  struct sshmac mac_;
  bytes key_;
};

class Hash {
public:
  Hash(int alg_id) {
    ASSERT(alg_ != -1);
    alg_ = alg_id;
    ctx_ = ssh_digest_start(alg_);
  }
  Hash(const std::string& alg_name)
      : Hash(ssh_digest_alg_by_name(alg_name.c_str())) {}

  Hash(const Hash&) = delete;
  Hash(Hash&&) = delete;
  Hash& operator=(const Hash&) = delete;
  Hash& operator=(Hash&&) = delete;

  size_t size() const {
    return ssh_digest_bytes(alg_);
  }

  size_t blockSize() const {
    return ssh_digest_blocksize(ctx_.get());
  }

  void write(bytes_view data) {
    ssh_digest_update(ctx_.get(), data.data(), data.size());
  }

  void write(uint8_t data) {
    ssh_digest_update(ctx_.get(), &data, 1);
  }

  bytes sum() {
    bytes digest;
    digest.resize(size());
    ASSERT(digest.size() > 0 && digest.size() <= SSH_DIGEST_MAX_LENGTH);
    if (auto r = ssh_digest_final(ctx_.get(), digest.data(), digest.size()); r != 0) {
      throw Envoy::EnvoyException(fmt::format("ssh_digest_final failed: {}", statusMessageFromErr(r)));
    }
    return digest;
  }

private:
  detail::ssh_digest_ctx_ptr ctx_;
  int alg_;
};

} // namespace openssh