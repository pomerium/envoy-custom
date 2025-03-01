#pragma once

#include <memory>
#include <string>

#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class AEADPacketCipher : public DirectionalPacketCipher,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  AEADPacketCipher(const char* cipher_name, bytes iv, bytes key, Mode mode);

  absl::Status decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override;
  absl::Status encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override;
  size_t blockSize() override;
  size_t aadSize() override;

protected:
  openssh::SshCipherCtxPtr ctx_;
  size_t block_len_;
  size_t aad_len_;
  size_t auth_len_;
  size_t iv_len_;
};

class Chacha20Poly1305Cipher : public AEADPacketCipher {
public:
  Chacha20Poly1305Cipher(bytes iv, bytes key, Mode mode)
      : AEADPacketCipher(cipherChacha20Poly1305, iv, key, mode) {}
};

class NoCipher : public DirectionalPacketCipher {
public:
  NoCipher() = default;
  absl::Status decryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override {
    uint32_t packlen = in.peekBEInt<uint32_t>();
    if (packlen < wire::MinPacketSize || packlen > wire::MaxPacketSize) {
      return absl::AbortedError("invalid packet size");
    }
    auto need = packlen + 4;
    if (in.length() < need) {
      return absl::AbortedError("short read");
    }
    out.move(in, need);
    return absl::OkStatus();
  }
  absl::Status encryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override {
    out.move(in);
    return absl::OkStatus();
  }
  size_t blockSize() override {
    // Minimum block size is 8 according to RFC4253 § 6
    return 8;
  }
  size_t aadSize() override {
    return 0;
  }
};

void generateKeyMaterial(bytes& out, const bytes& tag, KexResult* kex_result);

struct CipherMode {
  size_t keySize;
  size_t ivSize;

  std::function<std::unique_ptr<DirectionalPacketCipher>(bytes, bytes, Mode)> create;
};
static const std::map<std::string, CipherMode> cipherModes{
  {cipherChacha20Poly1305, {64, 0, [](bytes iv, bytes key, Mode mode) {
                              return std::make_unique<Chacha20Poly1305Cipher>(iv, key, mode);
                            }}}};

std::unique_ptr<PacketCipher> newPacketCipher(direction_t read, direction_t write,
                                              KexResult* kex_result);

std::unique_ptr<PacketCipher> newUnencrypted();
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec