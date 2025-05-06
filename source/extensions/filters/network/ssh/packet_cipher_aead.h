#pragma once

#include <memory>
#include <string>

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end
#include "source/common/common/logger.h"

#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class AEADPacketCipher : public DirectionalPacketCipher,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  AEADPacketCipher(const DerivedKeys& keys,
                   const DirectionAlgorithms& algs,
                   openssh::CipherMode mode);

  absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  absl::StatusOr<size_t> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  size_t blockSize() const override;
  size_t aadLen() const override;

protected:
  openssh::SSHCipher ctx_;
};

namespace detail {
class AEADPacketCipherFactory : public DirectionalPacketCipherFactory {
public:
  std::unique_ptr<DirectionalPacketCipher> create(const DerivedKeys& keys,
                                                  const DirectionAlgorithms& algs,
                                                  openssh::CipherMode mode) const override;
};
} // namespace detail

class Chacha20Poly1305CipherFactory final : public detail::AEADPacketCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{CipherChacha20Poly1305, 0}};
  }
  size_t ivSize() const override { return 0; }
  size_t keySize() const override { return 64; }
};

class AESGCM128CipherFactory final : public detail::AEADPacketCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{CipherAES128GCM, 1}};
  }
  size_t ivSize() const override { return 12; }
  size_t keySize() const override { return 16; }
};

class AESGCM256CipherFactory final : public detail::AEADPacketCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{CipherAES256GCM, 1}};
  }
  size_t ivSize() const override { return 12; }
  size_t keySize() const override { return 32; }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec