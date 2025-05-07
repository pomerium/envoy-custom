#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

PacketCipher::PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
                           std::unique_ptr<DirectionalPacketCipher> write)
    : read_(std::move(read)),
      write_(std::move(write)) {}

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
    return 1uz << (l / 4);
  }

  // cont.:
  //  If L is less than 128, [...] rekey at least once for every gigabyte
  //  of transmitted data.
  return 1uz << 30;
}

size_t PacketCipher::blockSize(openssh::CipherMode mode) {
  switch (mode) {
  case openssh::CipherMode::Read:
    return read_->blockSize();
  case openssh::CipherMode::Write:
    return write_->blockSize();
  }
  throw EnvoyException("unknown mode");
}

size_t PacketCipher::aadSize(openssh::CipherMode mode) {
  switch (mode) {
  case openssh::CipherMode::Read:
    return read_->aadLen();
  case openssh::CipherMode::Write:
    return write_->aadLen();
  }
  throw EnvoyException("unknown mode");
}

absl::StatusOr<size_t> NoCipher::decryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) {
  uint32_t packlen = in.peekBEInt<uint32_t>();
  if (packlen < wire::MinPacketSize || packlen > wire::MaxPacketSize) {
    return absl::AbortedError("invalid packet size");
  }
  uint32_t need = packlen + 4;
  if (in.length() < need) {
    return 0; // incomplete packet
  }
  out.move(in, need);
  return need;
}

absl::StatusOr<size_t> NoCipher::encryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) {
  size_t in_len = in.length();
  out.move(in, in_len);
  return in_len;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec