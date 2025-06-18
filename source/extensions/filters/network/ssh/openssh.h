#pragma once

#include <cstdlib>

#include "source/common/common/c_smart_ptr.h"

#include "source/extensions/filters/network/ssh/common.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/cipher.h"
#include "openssh/mac.h"
#include "openssh/digest.h"
}

namespace envoy::config::core::v3 {
class DataSource;
} // namespace envoy::config::core::v3
namespace corev3 = envoy::config::core::v3;

namespace openssh {

namespace detail {
using sshkey_ptr = Envoy::CSmartPtr<sshkey, sshkey_free>;
using sshmac_ptr = Envoy::CSmartPtr<sshmac, mac_clear>;
using sshcipher_ctx_ptr = Envoy::CSmartPtr<sshcipher_ctx, cipher_free>;
using ssh_digest_ctx_ptr = Envoy::CSmartPtr<ssh_digest_ctx, ssh_digest_free>;

using c_str_free_type = decltype([](void* p) { ::free(p); });
} // namespace detail

template <typename T = char>
using CStringPtr = std::unique_ptr<T, detail::c_str_free_type>;
using CBytesPtr = CStringPtr<uint8_t>;
using iv_bytes = bytes;
using key_bytes = bytes;

absl::StatusCode statusCodeFromErr(int n);
absl::Status statusFromErr(int n);
std::string statusMessageFromErr(int n);
std::string disconnectCodeToString(uint32_t n);
uint32_t statusCodeToDisconnectCode(absl::StatusCode code);

static constexpr auto ExtensionNoTouchRequired = "no-touch-required";
static constexpr auto ExtensionPermitX11Forwarding = "permit-X11-forwarding";
static constexpr auto ExtensionPermitPortForwarding = "permit-port-forwarding";
static constexpr auto ExtensionPermitPty = "permit-pty";
static constexpr auto ExtensionPermitUserRc = "permit-user-rc";

static constexpr uint32_t DefaultRSAKeySize = 3072;

class SSHKey {
public:
  SSHKey(const SSHKey&) = delete;
  SSHKey(SSHKey&&) = default;
  SSHKey& operator=(const SSHKey&) = delete;
  SSHKey& operator=(SSHKey&&) = default;

  bool operator==(const SSHKey& other) const;
  bool operator!=(const SSHKey& other) const;

  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPrivateKeyFile(const std::string& filepath);
  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPrivateKeyBytes(const std::string& bytes);
  static absl::StatusOr<std::unique_ptr<SSHKey>> fromPrivateKeyDataSource(const ::corev3::DataSource& ds);
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

  bytes toPublicKeyBlob() const;
  std::unique_ptr<SSHKey> toPublicKey() const;
  absl::StatusOr<std::string> formatPrivateKey(sshkey_private_format format = SSHKEY_PRIVATE_OPENSSH) const;
  std::string formatPublicKey() const;
  absl::StatusOr<bytes> sign(bytes_view payload, std::string alg = "") const;
  absl::Status verify(bytes_view signature, bytes_view payload, std::string alg = "");

  const struct sshkey* sshkeyForTest() const { return key_.get(); };

private:
  SSHKey(detail::sshkey_ptr key, CStringPtr<char> comment);

  const char* namePtr() const;

  detail::sshkey_ptr key_;
  CStringPtr<char> comment_;
};

using SSHKeyPtr = std::unique_ptr<SSHKey>;

// Returns the corresponding "plain" signing algorithm, or nullopt if unknown or unsupported.
std::optional<std::string> certSigningAlgorithmToPlain(const std::string& alg);

template <std::ranges::range R>
  requires std::same_as<typename R::value_type, corev3::DataSource>
absl::StatusOr<std::vector<openssh::SSHKeyPtr>> loadHostKeys(const R& data_sources) {
  std::vector<openssh::SSHKeyPtr> out;
  std::unordered_map<sshkey_types, std::string> keyTypes;
  for (typename R::size_type i = 0; i < std::size(data_sources); i++) {
    const auto& dataSource = data_sources[i];
    auto key = openssh::SSHKey::fromPrivateKeyDataSource(dataSource);
    if (!key.ok()) {
      return key.status();
    }
    std::string keyName = dataSource.has_filename()
                            ? dataSource.filename()
                            : fmt::format("(key {})", i);
    if (auto keyType = (*key)->keyTypePlain(); keyTypes.contains(keyType)) {
      ENVOY_LOG_MISC(error, "note: keys with algorithm {}: {}, {}", (*key)->keyTypeName(),
                     keyTypes.at(keyType), keyName);
      return absl::InvalidArgumentError("host keys must have unique algorithms");
    } else {
      keyTypes[keyType] = keyName;
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

  void compute(seqnum_t seqnum,
               Envoy::Buffer::Instance& out,
               const bytes_view& in);
  absl::Status verify(seqnum_t seqnum,
                      const bytes_view& data,
                      const bytes_view& mac);

  inline size_t length() const { return mac_.mac_len; }
  inline bool isETM() const { return mac_.etm != 0; }

  struct sshmac* sshmacForTest() { return &mac_; }

private:
  struct sshmac mac_;
  std::string name_;
  bytes key_;
};

class Hash {
public:
  Hash(int alg_id);
  Hash(const std::string& alg_name);

  Hash(const Hash&) = delete;
  Hash(Hash&&) = delete;
  Hash& operator=(const Hash&) = delete;
  Hash& operator=(Hash&&) = delete;

  size_t size() const;
  size_t blockSize() const;
  void write(bytes_view data);
  void write(uint8_t data);
  bytes sum();

private:
  detail::ssh_digest_ctx_ptr ctx_;
  int alg_;
};

} // namespace openssh