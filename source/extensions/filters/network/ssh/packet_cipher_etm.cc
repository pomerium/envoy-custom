#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "source/common/span.h"

#include "source/common/buffer/buffer_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ETMPacketCipher::ETMPacketCipher(const DerivedKeys& keys,
                                 const DirectionAlgorithms& algs,
                                 openssh::CipherMode mode)
    : ctx_(algs.cipher, keys.iv, keys.key, mode, 4),
      mac_(algs.mac, keys.mac) {
  if (!mac_.isETM()) {
    throw Envoy::EnvoyException(fmt::format("unsupported mac algorithm ({}): only etm mac algorithms are supported", algs.mac));
  }
}

absl::StatusOr<size_t> ETMPacketCipher::decryptPacket(uint32_t seqnum,
                                                      Envoy::Buffer::Instance& out,
                                                      Envoy::Buffer::Instance& in) {
  auto in_length = in.length();
  if (in_length < ctx_.blockSize()) {
    return 0; // incomplete packet
  }

  uint32_t packet_length = 0;
  auto l = ctx_.packetLength(seqnum, in);
  ASSERT(l.ok()); // can't fail for AES cipher modes
  packet_length = *l;
  const auto mac_len = mac_.length();
  size_t need = ctx_.aadLen() + packet_length + mac_len;
  if (in.length() < need) {
    return 0; // incomplete packet
  }

  auto input_view = linearizeToSpan(in).first(need);
  auto status = mac_.verify(seqnum, input_view.first(ctx_.aadLen() + packet_length), input_view.last(mac_len));
  if (!status.ok()) {
    return status;
  }
  auto stat = ctx_.decryptPacket(seqnum, out, in, packet_length);
  ASSERT(stat.ok()); // can't fail for AES-CTR cipher modes
  in.drain(mac_len);
  return packet_length;
}

absl::Status ETMPacketCipher::encryptPacket(uint32_t seqnum,
                                            Envoy::Buffer::Instance& out,
                                            Envoy::Buffer::Instance& in) {
  Envoy::Buffer::OwnedImpl tmp;
  auto stat = ctx_.encryptPacket(seqnum, tmp, in);
  ASSERT(stat.ok()); // can't fail for AES cipher modes
  mac_.compute(seqnum, tmp, linearizeToSpan(tmp));
  out.move(tmp);
  return absl::OkStatus();
}

size_t ETMPacketCipher::blockSize() const {
  return ctx_.blockSize();
}

size_t ETMPacketCipher::aadLen() const {
  return ctx_.aadLen();
}

std::unique_ptr<DirectionalPacketCipher> detail::AESCTRCipherFactory::create(const DerivedKeys& keys,
                                                                             const DirectionAlgorithms& algs,
                                                                             openssh::CipherMode mode) const {
  return std::make_unique<ETMPacketCipher>(keys, algs, mode);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec