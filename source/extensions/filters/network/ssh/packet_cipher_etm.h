#pragma once

#include <memory>
#include <string>

#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ETMPacketCipher : public DirectionalPacketCipher {
public:
  ETMPacketCipher(const DerivedKeys& keys,
                  const DirectionAlgorithms& algs,
                  openssh::CipherMode mode);

  absl::StatusOr<size_t> decryptPacket(uint32_t seqnum,
                                       Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  absl::Status encryptPacket(uint32_t seqnum,
                             Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override;
  size_t blockSize() const override;
  size_t aadLen() const override;

protected:
  openssh::SSHCipher ctx_;
  openssh::SSHMac mac_;
};

namespace detail {
class AESCTRCipherFactory : public DirectionalPacketCipherFactory {
public:
  std::unique_ptr<DirectionalPacketCipher> create(const DerivedKeys& keys,
                                                  const DirectionAlgorithms& algs,
                                                  openssh::CipherMode mode) const override;
  size_t ivSize() const override { return AES_BLOCK_SIZE; };
};
} // namespace detail

class AES128CTRCipherFactory final : public detail::AESCTRCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{CipherAES128CTR, 2}};
  }
  size_t keySize() const override { return 16; };
};

class AES192CTRCipherFactory final : public detail::AESCTRCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{CipherAES192CTR, 2}};
  }
  size_t keySize() const override { return 24; };
};

class AES256CTRCipherFactory final : public detail::AESCTRCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{CipherAES256CTR, 2}};
  }
  size_t keySize() const override { return 32; };
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec