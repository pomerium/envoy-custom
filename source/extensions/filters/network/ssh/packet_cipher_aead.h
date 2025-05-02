#pragma once

#include <memory>
#include <string>

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end
#include "source/common/common/logger.h"

#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class AEADPacketCipher : public DirectionalPacketCipher,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  AEADPacketCipher(const char* cipher_name, bytes iv, bytes key, openssh::CipherMode mode);

  absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  absl::StatusOr<size_t> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  size_t blockSize() const override;
  size_t aadLen() const override;

protected:
  openssh::SSHCipher ctx_;
};

class Chacha20Poly1305CipherFactory final : public DirectionalPacketCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{cipherChacha20Poly1305, 0}};
  }
  std::unique_ptr<DirectionalPacketCipher> create(const bytes& iv, const bytes& key, openssh::CipherMode mode) const override {
    ASSERT(iv.size() == ivSize());
    ASSERT(key.size() == keySize());
    return std::make_unique<AEADPacketCipher>(cipherChacha20Poly1305, iv, key, mode);
  }
  size_t keySize() const override { return 64; }
  size_t ivSize() const override { return 0; }
};

class AESGCM128CipherFactory final : public DirectionalPacketCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{cipherAES128GCM, 1}};
  }
  std::unique_ptr<DirectionalPacketCipher> create(const bytes& iv, const bytes& key, openssh::CipherMode mode) const override {
    return std::make_unique<AEADPacketCipher>(cipherAES128GCM, iv, key, mode);
  }
  size_t keySize() const override { return 16; }
  size_t ivSize() const override { return 12; }
};

class AESGCM256CipherFactory final : public DirectionalPacketCipherFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{cipherAES256GCM, 1}};
  }
  std::unique_ptr<DirectionalPacketCipher> create(const bytes& iv, const bytes& key, openssh::CipherMode mode) const override {
    return std::make_unique<AEADPacketCipher>(cipherAES256GCM, iv, key, mode);
  }
  size_t keySize() const override { return 32; }
  size_t ivSize() const override { return 12; }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec