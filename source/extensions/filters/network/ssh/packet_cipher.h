#pragma once

#include "envoy/buffer/buffer.h"

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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
