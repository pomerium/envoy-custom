#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

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