#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"

#include <cstdint>

#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

AEADPacketCipher::AEADPacketCipher(const DerivedKeys& keys,
                                   const DirectionAlgorithms& algs,
                                   openssh::CipherMode mode)
    : ctx_(openssh::SSHCipher(algs.cipher, keys.iv, keys.key, mode, 4)) {}

absl::StatusOr<size_t> AEADPacketCipher::decryptPacket(uint32_t seqnum,
                                                       Envoy::Buffer::Instance& out,
                                                       Envoy::Buffer::Instance& in) {
  auto in_length = in.length();
  if (in_length < ctx_.blockSize()) {
    return 0; // incomplete packet
  }

  uint32_t packlen = 0;
  if (auto l = ctx_.packetLength(seqnum, in); !l.ok()) {
    return l.status();
  } else {
    packlen = *l;
  }
  size_t need = ctx_.aadLen() + packlen + ctx_.authLen();
  if (in.length() < need) {
    return 0; // incomplete packet
  }

  auto r = ctx_.decryptPacket(seqnum, out, in, packlen);
  if (!r.ok()) {
    return r.status();
  }

  return *r;
}

absl::StatusOr<size_t> AEADPacketCipher::encryptPacket(uint32_t seqnum,
                                                       Envoy::Buffer::Instance& out,
                                                       Envoy::Buffer::Instance& in) {

  return ctx_.encryptPacket(seqnum, out, in);
}

size_t AEADPacketCipher::blockSize() const {
  return ctx_.blockSize();
};

size_t AEADPacketCipher::aadLen() const {
  return ctx_.aadLen();
};

std::unique_ptr<DirectionalPacketCipher> detail::AEADPacketCipherFactory::create(const DerivedKeys& keys,
                                                                                 const DirectionAlgorithms& algs,
                                                                                 openssh::CipherMode mode) const {
  ASSERT(keys.iv.size() == ivSize());
  ASSERT(keys.key.size() == keySize());
  return std::make_unique<AEADPacketCipher>(keys, algs, mode);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec