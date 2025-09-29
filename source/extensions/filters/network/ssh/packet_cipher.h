#pragma once

#include <cstdint>

#include "envoy/buffer/buffer.h"
#include "source/common/factory.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DirectionalPacketCipher {
public:
  virtual ~DirectionalPacketCipher() = default;
  // Decrypts one packet from the input buffer and writes the plaintext to the output buffer.
  // Drains bytes from the input buffer.
  // Returns the number of bytes *decrypted*, which will usually be less than the number of
  // bytes read.
  // If the buffer does not contain an entire packet, it will not drain any bytes and will
  // return 0.
  virtual absl::StatusOr<size_t> decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) PURE;
  virtual absl::Status encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                     Envoy::Buffer::Instance& in) PURE;
  virtual size_t blockSize() const PURE;
  virtual size_t aadLen() const PURE;
};

using iv_type = bytes;
using key_type = bytes;
using mac_type = bytes;

struct DerivedKeys {
  bytes iv;
  bytes key;
  bytes mac;
};

class DirectionalPacketCipherFactory {
public:
  virtual ~DirectionalPacketCipherFactory() = default;
  virtual std::vector<std::pair<std::string, priority_t>> names() const PURE;
  virtual std::unique_ptr<DirectionalPacketCipher> create(const DerivedKeys& keys,
                                                          const DirectionAlgorithms& algs,
                                                          openssh::CipherMode mode) const PURE;
  virtual size_t ivSize() const PURE;
  virtual size_t keySize() const PURE;
};

class DirectionalPacketCipherFactoryRegistry : public PriorityAwareFactoryRegistry<DirectionalPacketCipherFactory,
                                                                                   DirectionalPacketCipher,
                                                                                   const DerivedKeys&,
                                                                                   const DirectionAlgorithms&,
                                                                                   openssh::CipherMode> {};
using DirectionalPacketCipherFactoryPtr = std::unique_ptr<DirectionalPacketCipherFactory>;

class PacketCipher {
public:
  PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
               std::unique_ptr<DirectionalPacketCipher> write);

  absl::Status encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
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

class NoCipher final : public DirectionalPacketCipher {
public:
  NoCipher() = default;
  absl::StatusOr<size_t> decryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                       Envoy::Buffer::Instance& in) override;
  absl::Status encryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                             Envoy::Buffer::Instance& in) override;
  size_t blockSize() const override {
    // Minimum block size is 8 according to RFC4253 § 6
    return 8;
  }
  size_t aadLen() const override { return 0; }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
