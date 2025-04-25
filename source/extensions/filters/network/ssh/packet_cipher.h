#pragma once

#include <cstdint>

#include "envoy/buffer/buffer.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DirectionalPacketCipher {
public:
  virtual ~DirectionalPacketCipher() = default;
  virtual absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) PURE;
  virtual absl::StatusOr<size_t> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) PURE;
  virtual size_t blockSize() PURE;
  virtual size_t aadLen() PURE;
};

class PacketCipher {
public:
  PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
               std::unique_ptr<DirectionalPacketCipher> write);
  absl::StatusOr<size_t> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in);
  absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in);
  size_t blockSize(openssh::CipherMode mode);
  size_t aadSize(openssh::CipherMode mode);
  size_t rekeyAfterBytes(openssh::CipherMode mode);

private:
  std::unique_ptr<DirectionalPacketCipher> read_;
  std::unique_ptr<DirectionalPacketCipher> write_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
