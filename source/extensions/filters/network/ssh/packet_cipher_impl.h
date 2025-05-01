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
  size_t blockSize() override;
  size_t aadLen() override;

protected:
  openssh::SSHCipher ctx_;
};

class Chacha20Poly1305Cipher final : public AEADPacketCipher {
public:
  Chacha20Poly1305Cipher(bytes iv, bytes key, openssh::CipherMode mode)
      : AEADPacketCipher(cipherChacha20Poly1305, iv, key, mode) {}
};

class AESGCM128Cipher final : public AEADPacketCipher {
public:
  AESGCM128Cipher(bytes iv, bytes key, openssh::CipherMode mode)
      : AEADPacketCipher(cipherAES128GCM, iv, key, mode) {}
};

class AESGCM256Cipher final : public AEADPacketCipher {
public:
  AESGCM256Cipher(bytes iv, bytes key, openssh::CipherMode mode)
      : AEADPacketCipher(cipherAES256GCM, iv, key, mode) {}
};

class NoCipher final : public DirectionalPacketCipher {
public:
  NoCipher() = default;
  absl::StatusOr<size_t> decryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  absl::StatusOr<size_t> encryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  size_t blockSize() override;
  size_t aadLen() override;
};

struct CipherSpec {
  size_t keySize;
  size_t ivSize;

  std::function<std::unique_ptr<DirectionalPacketCipher>(bytes, bytes, openssh::CipherMode)> create;
};

// clang-format off
static const std::map<std::string, CipherSpec> ciphers{
  {
    cipherChacha20Poly1305, {
      .keySize = 64,
      .ivSize  = 0,
      .create  = [](bytes iv, bytes key, openssh::CipherMode mode) {
        return std::make_unique<Chacha20Poly1305Cipher>(iv, key, mode);
      }
    }
  },
  {
    cipherAES128GCM, {
      .keySize = 16,
      .ivSize = 12,
      .create = [](bytes iv, bytes key, openssh::CipherMode mode) {
        return std::make_unique<AESGCM128Cipher>(iv, key, mode);
      }
    },
  },
  {
    cipherAES256GCM, {
      .keySize = 32,
      .ivSize = 12,
      .create = [](bytes iv, bytes key, openssh::CipherMode mode) {
        return std::make_unique<AESGCM256Cipher>(iv, key, mode);
      }
    }
  }
};
// clang-format on

class PacketCipherFactory : public Logger::Loggable<Logger::Id::filter> {
public:
  static std::unique_ptr<PacketCipher> makePacketCipher(direction_t read,
                                                        direction_t write,
                                                        KexResult* kex_result);
  static std::unique_ptr<PacketCipher> makeUnencryptedPacketCipher();
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec