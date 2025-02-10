#pragma once

#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include <memory>
#include <string>

extern "C" {
#include "openssh/cipher.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

constexpr auto PACKET_MAX_SIZE = (256 * 1024);
enum Mode {
  MODE_WRITE = CIPHER_ENCRYPT,
  MODE_READ = CIPHER_DECRYPT,
};

class DirectionalPacketCipher {
public:
  virtual ~DirectionalPacketCipher() = default;
  virtual absl::Status decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                     Envoy::Buffer::Instance& in) PURE;
  virtual absl::Status encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                     Envoy::Buffer::Instance& in) PURE;
  virtual size_t blockSize() PURE;
  virtual size_t aadSize() PURE;
};

struct cipher_mode_t {
  size_t keySize;
  size_t ivSize;

  std::function<std::unique_ptr<DirectionalPacketCipher>(bytearray, bytearray, Mode)> create;
};

class PacketCipher {
public:
  PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
               std::unique_ptr<DirectionalPacketCipher> write);
  absl::Status encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in);
  absl::Status decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in);
  size_t blockSize(Mode mode);
  size_t aadSize(Mode mode);

private:
  std::unique_ptr<DirectionalPacketCipher> read_;
  std::unique_ptr<DirectionalPacketCipher> write_;
};

class AEADPacketCipher : public DirectionalPacketCipher {
public:
  AEADPacketCipher(const char* cipher_name, bytearray iv, bytearray key, Mode mode);

  absl::Status decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override;
  absl::Status encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override;
  size_t blockSize() override;
  size_t aadSize() override;

protected:
  libssh::UniquePtr<sshcipher_ctx> ctx_;
  size_t block_len_;
  size_t aad_len_;
  size_t auth_len_;
  size_t iv_len_;
};

class Chacha20Poly1305Cipher : public AEADPacketCipher {
public:
  Chacha20Poly1305Cipher(bytearray iv, bytearray key, Mode mode)
      : AEADPacketCipher(cipherChacha20Poly1305, iv, key, mode) {}
};

class NoCipher : public DirectionalPacketCipher {
public:
  NoCipher() = default;
  absl::Status decryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override {
    uint32_t packlen = in.peekBEInt<uint32_t>();
    if (packlen < 5 || packlen > PACKET_MAX_SIZE) {
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
  size_t blockSize() override { return 8; }
  size_t aadSize() override { return 0; }
};

void generateKeyMaterial(bytearray& out, const bytearray& tag, kex_result_t* kex_result);

static const std::map<std::string, cipher_mode_t> cipherModes{
    {cipherChacha20Poly1305, {64, 0, [](bytearray iv, bytearray key, Mode mode) {
                                return std::make_unique<Chacha20Poly1305Cipher>(iv, key, mode);
                              }}}};

std::unique_ptr<PacketCipher> NewPacketCipher(direction_t read, direction_t write,
                                              kex_result_t* kex_result);

std::unique_ptr<PacketCipher> NewUnencrypted();
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec