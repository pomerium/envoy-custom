#pragma once

#include <cstddef>
#include <cstdint>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/random_generator.h"

#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"

namespace wire {

// Returns the padding length according to RFC4253 § 6 for the given payload length, cipher block
// size, and aad length.
inline uint8_t paddingLength(uint32_t payload_length, uint32_t cipher_block_size) noexcept {
  SECURITY_ASSERT((cipher_block_size & (cipher_block_size - 1)) == 0,
                  fmt::format("bug: invalid cipher block size of {}", cipher_block_size));
  if (cipher_block_size < 8) [[unlikely]] {
    cipher_block_size = 8;
  }
  uint32_t padding_length = cipher_block_size - ((4 + 1 + payload_length) % cipher_block_size);
  if (padding_length < 4) {
    padding_length += cipher_block_size;
  }
  return static_cast<uint8_t>(padding_length);
}

// Returns the payload length according to RFC4253 § 6 for the given packet and padding lengths.
inline absl::StatusOr<uint32_t> payloadLength(uint32_t packet_length, uint8_t padding_length) noexcept {
  if (padding_length < 4) [[unlikely]] {
    return absl::InvalidArgumentError("invalid padding length");
  }
  if (packet_length < MinPacketSize || packet_length > MaxPacketSize ||
      packet_length < (padding_length + sizeof(padding_length))) [[unlikely]] {
    return absl::InvalidArgumentError("invalid packet length");
  }

  return packet_length - (padding_length + 1);
}

template <Decoder T>
absl::StatusOr<size_t> decodePacket(Envoy::Buffer::Instance& buffer, T& payload) noexcept {
  size_t n = 0;
  uint32_t packet_length{};
  uint8_t padding_length{};

  try {
    n += read(buffer, packet_length, sizeof(packet_length));
    n += read(buffer, padding_length, sizeof(padding_length));
  } catch (const Envoy::EnvoyException& e) {
    return absl::InvalidArgumentError(fmt::format("error decoding packet: {}", e.what()));
  }

  auto expectedPayloadLen = payloadLength(packet_length, padding_length);
  if (!expectedPayloadLen.ok()) {
    return expectedPayloadLen.status();
  }
  auto actualPayloadLen = payload.decode(buffer, *expectedPayloadLen);
  if (!actualPayloadLen.ok()) {
    return actualPayloadLen.status();
  }
  if (*actualPayloadLen != *expectedPayloadLen) {
    return absl::InvalidArgumentError(fmt::format(
      "unexpected packet payload size of {} bytes (expected {})", n, *expectedPayloadLen));
  }
  n += *actualPayloadLen;

  if (buffer.length() < padding_length) {
    return absl::InvalidArgumentError("short read");
  }
  buffer.drain(padding_length);
  n += padding_length;
  return n;
}

template <Encoder T>
absl::StatusOr<size_t> encodePacket(Envoy::Buffer::Instance& out, const T& msg,
                                    size_t cipher_block_size = 8,
                                    size_t aad_len = 0,
                                    bool random_padding = true) noexcept {
  Envoy::Buffer::OwnedImpl payloadBytes;
  auto payload_length = msg.encode(payloadBytes);
  if (!payload_length.ok()) {
    return payload_length.status();
  }
  if (*payload_length == 0) [[unlikely]] {
    return absl::InvalidArgumentError("message encoded to 0 bytes");
  }

  uint8_t padding_length = paddingLength(static_cast<uint32_t>(*payload_length - aad_len),
                                         static_cast<uint32_t>(cipher_block_size));
  uint32_t packet_length = static_cast<uint32_t>(*payload_length) +
                           static_cast<uint32_t>(sizeof(padding_length)) +
                           static_cast<uint32_t>(padding_length);

  if (packet_length > MaxPacketSize) [[unlikely]] {
    return absl::InvalidArgumentError("encoded message is larger than the max packet size");
  }

  size_t n = 0;
  n += write(out, packet_length);
  n += write(out, padding_length);
  out.move(payloadBytes);
  n += *payload_length;

  std::vector<uint64_t> padding((padding_length / 8) + ((padding_length % 8) == 0 ? 0 : 1), 0);
  if (random_padding) {
    for (size_t i = 0; i < padding.size(); i++) {
      padding[i] = Envoy::Random::RandomUtility::random();
    }
  }
  out.add(std::string_view(unsafe_forge_span(reinterpret_cast<char*>(padding.data()), padding_length)));
  n += padding_length;

  return n;
}

} // namespace wire