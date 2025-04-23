#pragma once

#include <cstdint>

#include "envoy/buffer/buffer.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum Mode {
  ModeRead = 0,  // CIPHER_DECRYPT
  ModeWrite = 1, // CIPHER_ENCRYPT
};

class DirectionalPacketCipher {
public:
  virtual ~DirectionalPacketCipher() = default;
  virtual absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) PURE;
  virtual absl::StatusOr<size_t> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) PURE;
  virtual size_t blockSize() PURE;
  virtual size_t aadSize() PURE;
};

class PacketCipher {
public:
  PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
               std::unique_ptr<DirectionalPacketCipher> write);
  absl::StatusOr<size_t> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in);
  absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in);
  size_t blockSize(Mode mode);
  size_t aadSize(Mode mode);
  size_t rekeyAfterBytes(Mode mode);

private:
  std::unique_ptr<DirectionalPacketCipher> read_;
  std::unique_ptr<DirectionalPacketCipher> write_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
