#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"

#include <cstdint>
#include <algorithm>
#include <iterator>

#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

PacketCipher::PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
                           std::unique_ptr<DirectionalPacketCipher> write)
    : read_(std::move(read)), write_(std::move(write)) {}

absl::StatusOr<size_t> PacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                   Envoy::Buffer::Instance& in) {
  return write_->encryptPacket(seqnum, out, in);
}

absl::StatusOr<size_t> PacketCipher::decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                   Envoy::Buffer::Instance& in) {
  return read_->decryptPacket(seqnum, out, in);
}

size_t PacketCipher::rekeyAfterBytes(openssh::CipherMode mode) {
  // RFC4344 § 3.2 states:
  //  Let L be the block length (in bits) of an SSH encryption method's
  //  block cipher (e.g., 128 for AES).  If L is at least 128, then, after
  //  rekeying, an SSH implementation SHOULD NOT encrypt more than 2**(L/4)
  //  blocks before rekeying again.

  auto l = blockSize(mode) * 8;
  if (l >= 128) {
    return 1 << (l / 4);
  }

  // cont.:
  //  If L is less than 128, [...] rekey at least once for every gigabyte
  //  of transmitted data.
  return 1 << 30;
}

AEADPacketCipher::AEADPacketCipher(const char* cipher_name, bytes iv, bytes key,
                                   openssh::CipherMode mode)
    : ctx_(openssh::SSHCipher(cipher_name, iv, key, mode)) {}

absl::StatusOr<size_t> AEADPacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                       Envoy::Buffer::Instance& in) {

  return ctx_.encryptPacket(seqnum, out, in);
}

absl::StatusOr<size_t> AEADPacketCipher::decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
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

  auto r = ctx_.decryptPacket(seqnum, out, in, packlen);
  if (!r.ok()) {
    return r.status();
  }

  return *r;
}

size_t AEADPacketCipher::blockSize() const {
  return ctx_.blockSize();
};

size_t AEADPacketCipher::aadLen() const {
  return ctx_.aadLen();
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec