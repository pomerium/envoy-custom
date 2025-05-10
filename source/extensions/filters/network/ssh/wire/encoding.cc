#include "source/extensions/filters/network/ssh/wire/encoding.h"

namespace wire {

size_t writeBignum(Envoy::Buffer::Instance& buffer, std::span<const uint8_t> in) {
  // skip leading zeros
  in = in.subspan(std::distance(in.begin(), std::find_if(in.begin(), in.end(),
                                                         [](const uint8_t& b) { return b != 0; })));
  size_t in_size = in.size();
  if (in_size > (16384 / 8)) { // this limit is SSHBUF_MAX_BIGNUM from sshbuf.h
    throw Envoy::EnvoyException("input too large");
  }
  // prepend a zero byte if the most significant bit is set
  auto prepend = (in_size > 0 && (in[0] & 0x80) != 0);
  buffer.writeBEInt(static_cast<uint32_t>(prepend ? (in_size + 1) : in_size));
  size_t n = 4;
  if (prepend) {
    buffer.writeByte(0);
    n++;
  }
  buffer.add(in.data(), in_size);
  n += in_size;
  return n;
}

absl::StatusOr<size_t> encodeSequence(Envoy::Buffer::Instance&) {
  return 0;
}

size_t read(Envoy::Buffer::Instance& buffer, bool& t, size_t limit) {
  if (limit == 0 || buffer.length() < limit) {
    // zero-length integral types are not allowed
    throw Envoy::EnvoyException("short read");
  }
  t = buffer.drainBEInt<uint8_t>() != 0;
  return sizeof(t);
}

size_t write(Envoy::Buffer::Instance& buffer, const bool& t) {
  buffer.writeByte<uint8_t>(t ? 1 : 0);
  return sizeof(t);
}

} // namespace wire