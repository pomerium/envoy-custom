#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "source/common/span.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ETMPacketCipher::ETMPacketCipher(const DerivedKeys& keys,
                                 const DirectionAlgorithms& algs,
                                 openssh::CipherMode mode)
    : ctx_(algs.cipher, keys.iv, keys.key, mode, 4),
      mac_(algs.mac, keys.mac) {
  ASSERT(mac_.isETM(), "only etm mac algorithms are supported");
}

absl::StatusOr<size_t> ETMPacketCipher::decryptPacket(uint32_t seqnum,
                                                      Envoy::Buffer::Instance& out,
                                                      Envoy::Buffer::Instance& in) {
  auto in_length = in.length();
  if (in_length < ctx_.blockSize()) {
    return 0; // incomplete packet
  }

  uint32_t packet_length = 0;
  if (auto l = ctx_.packetLength(seqnum, in); !l.ok()) {
    return l.status();
  } else {
    packet_length = *l;
  }
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
  auto r = ctx_.decryptPacket(seqnum, out, in, packet_length);
  if (!r.ok()) {
    return r.status();
  }
  ASSERT(*r == need - mac_len);
  in.drain(mac_len);
  return packet_length;
}

absl::StatusOr<size_t> ETMPacketCipher::encryptPacket(uint32_t seqnum,
                                                      Envoy::Buffer::Instance& out,
                                                      Envoy::Buffer::Instance& in) {
  Envoy::Buffer::OwnedImpl tmp;
  auto enc_len = ctx_.encryptPacket(seqnum, tmp, in);
  if (!enc_len.ok()) {
    return enc_len.status();
  }
  ASSERT(*enc_len == tmp.length());
  if (auto r = mac_.compute(seqnum, tmp, linearizeToSpan(tmp)); !r.ok()) {
    return r.status();
  }
  out.move(tmp);
  return *enc_len;
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