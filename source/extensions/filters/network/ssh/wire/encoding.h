#pragma once

#include <concepts>
#include <cstdint>
#include <algorithm>
#include <string>
#include <type_traits>

#include "openssl/rand.h"

#include "source/common/buffer/buffer_impl.h"

#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace wire {

inline size_t read(Envoy::Buffer::Instance& buffer, SshMessageType& t, size_t) {
  t = buffer.drainInt<SshMessageType>();
  return 1;
}

inline size_t write(Envoy::Buffer::Instance& buffer, const SshMessageType& t) {
  buffer.writeByte(t);
  return 1;
}

template <typename T>
inline size_t split(Envoy::Buffer::Instance& buffer, std::vector<T>& out, size_t limit, char delimiter) {
  if (buffer.length() < limit) {
    throw EnvoyException("short read");
  }
  static_assert(sizeof(typename T::value_type) == 1);

  size_t n = 0;
  auto size = buffer.drainBEInt<uint32_t>();
  n += sizeof(size);
  if (buffer.length() < size) {
    throw EnvoyException(fmt::format("string has invalid length {}", size));
  }
  T current;
  for (size_t i = 0; i < size; i++) {
    auto c = buffer.drainInt<typename T::value_type>();
    n++;
    if (c == delimiter) {
      if (current.size() > 0) {
        out.push_back(std::move(current));
        current.clear();
      }
      continue;
    }
    current.push_back(c);
  }
  if (current.size() > 0) {
    out.push_back(std::move(current));
  }
  return n;
}

// equivalent to sshbuf_put_bignum2_bytes
inline void writeBignum(Envoy::Buffer::Instance& buffer, std::span<const uint8_t> str) {
  // skip leading zeros
  str = str.subspan(std::distance(str.begin(),
                                  std::find_if(str.begin(), str.end(),
                                               [](const uint8_t& b) { return b != 0; })));
  size_t len = str.size();
  // prepend a zero byte if the most significant bit is set
  auto prepend = (len > 0 && (str[0] & 0x80) != 0);
  buffer.writeBEInt<uint32_t>(prepend ? (len + 1) : len);
  if (prepend) {
    buffer.writeByte(0);
  }
  buffer.add(str.data(), str.size());
}

inline bytes flushToBytes(Envoy::Buffer::Instance& buf) {
  bytes out;
  size_t n = buf.length();
  out.resize(n);
  buf.copyOut(0, n, out.data());
  buf.drain(n);
  return out;
}

inline void flushToBytes(Envoy::Buffer::Instance& buf, bytes& out) {
  size_t n = buf.length();
  out.resize(n);
  buf.copyOut(0, n, out.data());
  buf.drain(n);
}

template <typename T>
concept Encoder = requires(T t) {
  { t.encode(std::declval<Envoy::Buffer::Instance&>()) };
};

template <typename T>
concept Decoder = requires(T t) {
  { t.decode(std::declval<Envoy::Buffer::Instance&>(), std::declval<size_t>()) };
};

template <typename T>
  requires Encoder<T>
inline bytes encodeToBytes(const T& t) {
  Envoy::Buffer::OwnedImpl tmp;
  t.encode(tmp);
  return flushToBytes(tmp);
}

template <typename T>
inline size_t read(Envoy::Buffer::Instance& buffer, T& t, size_t n) = delete;

template <typename T>
inline size_t write(Envoy::Buffer::Instance& buffer, const T& t) = delete;

// read/write uint32
inline size_t read(Envoy::Buffer::Instance& buffer, uint32_t& t, size_t limit) {
  if (buffer.length() < limit) {
    throw EnvoyException("short read");
  }
  t = buffer.drainBEInt<uint32_t>();
  return sizeof(t);
}
inline size_t write(Envoy::Buffer::Instance& buffer, const uint32_t& t) {
  buffer.writeBEInt<uint32_t>(t);
  return sizeof(t);
}

// read/write bool
inline size_t read(Envoy::Buffer::Instance& buffer, bool& t, size_t limit) {
  if (buffer.length() < limit) {
    throw EnvoyException("short read");
  }
  t = static_cast<bool>(buffer.drainBEInt<uint8_t>());
  return sizeof(t);
}
inline size_t write(Envoy::Buffer::Instance& buffer, const bool& t) {
  buffer.writeBEInt<uint8_t>(t);
  return sizeof(t);
}

// read/write uint8
inline size_t read(Envoy::Buffer::Instance& buffer, uint8_t& t, size_t limit) {
  if (buffer.length() < limit) {
    throw EnvoyException("short read");
  }
  t = buffer.drainBEInt<uint8_t>();
  return sizeof(t);
}

inline size_t write(Envoy::Buffer::Instance& buffer, const uint8_t& t) {
  buffer.writeBEInt<uint8_t>(t);
  return sizeof(t);
}

// read/write string
inline size_t read(Envoy::Buffer::Instance& buffer, std::string& t, size_t size) {
  if (buffer.length() < size) {
    throw EnvoyException("short read");
  }
  t.resize(size);
  buffer.copyOut(0, size, t.data());
  buffer.drain(size);
  return size;
}

inline size_t write(Envoy::Buffer::Instance& buffer, const std::string& t) {
  buffer.add(t.data(), t.size());
  return t.size();
}

// read/write bytes
inline size_t read(Envoy::Buffer::Instance& buffer, bytes& t, size_t size) {
  if (buffer.length() < size) {
    throw EnvoyException("short read");
  }
  t.resize(size);
  buffer.copyOut(0, size, t.data());
  buffer.drain(size);
  return size;
}

inline size_t write(Envoy::Buffer::Instance& buffer, const bytes& t) {
  buffer.add(t.data(), t.size());
  return t.size();
}

// read/write arrays
template <size_t N>
inline size_t read(Envoy::Buffer::Instance& buffer, fixed_bytes<N>& t, size_t limit) {
  if (buffer.length() < N || N > limit) {
    throw EnvoyException("short read");
  }
  buffer.copyOut(0, N, t.data());
  buffer.drain(N);
  return N;
}
template <size_t N>
inline size_t write(Envoy::Buffer::Instance& buffer, const fixed_bytes<N>& t) {
  buffer.add(t.data(), t.size());
  return N;
}

template <typename T>
  requires Decoder<T>
absl::StatusOr<T> readPacket(Envoy::Buffer::Instance& buffer) noexcept {
  try {
    size_t n = 0;
    uint32_t packet_length{};
    uint8_t padding_length{};
    n += read(buffer, packet_length, sizeof(packet_length));
    n += read(buffer, padding_length, sizeof(padding_length));
    T payload{};
    {
      auto payload_expected_size = packet_length - padding_length - 1;
      auto payload_actual_size = payload.decode(buffer, payload_expected_size);
      if (payload_actual_size != payload_expected_size) {
        return absl::InvalidArgumentError(fmt::format(
            "unexpected packet payload size of {} bytes (expected {})", n, payload_expected_size));
      }
      n += payload_actual_size;
    }
    bytes padding(padding_length);
    n += read(buffer, padding, static_cast<size_t>(padding_length));
    return payload;
  } catch (const EnvoyException& e) {
    return absl::InternalError(fmt::format("error decoding packet: {}", e.what()));
  }
}

template <typename T>
  requires Encoder<T>
inline size_t writePacket(Envoy::Buffer::Instance& out, const T& msg,
                          size_t cipher_block_size = 8, size_t aad_len = 0) {
  Envoy::Buffer::OwnedImpl payloadBytes;
  size_t payload_length = msg.encode(payloadBytes);

  // RFC4253 § 6
  uint8_t padding_length = cipher_block_size - ((5 + payload_length - aad_len) % cipher_block_size);
  if (padding_length < 4) {
    padding_length += cipher_block_size;
  }
  uint32_t packet_length = sizeof(padding_length) + payload_length + padding_length;

  size_t n = 0;
  n += write(out, packet_length);
  n += write(out, padding_length);
  out.move(payloadBytes);
  n += payload_length;

  bytes padding(padding_length, 0);
  RAND_bytes(padding.data(), padding.size());
  n += write(out, padding);
  return n;
}

// NB: all specializations of read/write in this file must be defined before the concept definitions

template <typename T>
concept Reader = requires(T& t) {
  { read(std::declval<Envoy::Buffer::Instance&>(), t, size_t{}) } -> std::same_as<size_t>;
};

template <typename T>
concept Writer = requires(const T& t) {
  { write(std::declval<Envoy::Buffer::Instance&>(), t) } -> std::same_as<size_t>;
};

template <typename T>
concept ReadWriter = Reader<T> && Writer<T>;

enum EncodingOptions : uint32_t {
  None = 0,
  LengthPrefixed = 1 << 0,
  CommaDelimited = 1 << 1,
  ListSizePrefixed = 1 << 2,
  ListLengthPrefixed = 1 << 3,
  Conditional = 1 << 4,

  NameListFormat = CommaDelimited | ListLengthPrefixed,
};

constexpr inline EncodingOptions operator|(EncodingOptions lhs, EncodingOptions rhs) {
  return static_cast<EncodingOptions>(
      static_cast<std::underlying_type_t<EncodingOptions>>(lhs) |
      static_cast<std::underlying_type_t<EncodingOptions>>(rhs));
}

// read function for standard field types
template <EncodingOptions Opt, typename T>
std::enable_if_t<(!is_vector<T>::value || std::is_same_v<T, bytes>), size_t>
read_opt(Envoy::Buffer::Instance& buffer, T& value, size_t n) {
  if constexpr (Opt & LengthPrefixed) {
    uint32_t entry_len = buffer.drainBEInt<uint32_t>();
    return 4 + read(buffer, value, entry_len);
  } else {
    return read(buffer, value, n);
  }
}

// write function for standard field types
template <EncodingOptions Opt, typename T>
std::enable_if_t<(!is_vector<T>::value || std::is_same_v<T, bytes>), size_t>
write_opt(Envoy::Buffer::Instance& buffer, const T& value) {
  if constexpr (Opt & LengthPrefixed) {
    Envoy::Buffer::OwnedImpl tmp;
    auto size = write(tmp, value);
    buffer.writeBEInt<uint32_t>(size);
    buffer.move(tmp);
    return 4 + size;
  }
  return write(buffer, value);
}

// read function for fields of list types, which make use of field options to control list encoding.
template <EncodingOptions Opt, typename T>
  requires Reader<typename T::value_type>
std::enable_if_t<(is_vector<T>::value && !std::is_same_v<T, bytes>), size_t>
read_opt(Envoy::Buffer::Instance& buffer, T& value, size_t limit) {
  if (buffer.length() < limit) {
    throw EnvoyException("short read");
  }
  using value_type = typename T::value_type;
  uint32_t list_len{};
  size_t n = 0;
  if (Opt & ListSizePrefixed) {
    list_len = buffer.drainBEInt<uint32_t>();
    n += 4;
  }
  if constexpr (Opt & CommaDelimited) {
    std::vector<bytes> raw_entries;
    n += split(buffer, raw_entries, limit - n, ',');
    for (const auto& raw_entry : raw_entries) {
      Envoy::Buffer::OwnedImpl tmp; // todo
      tmp.add(raw_entry.data(), raw_entry.size());
      value_type t{};
      read(tmp, t, tmp.length());
      value.push_back(std::move(t));
    }
  } else if constexpr (Opt & LengthPrefixed) {
    size_t accum = 0;
    while (accum < limit - n) {
      uint32_t entry_len = buffer.drainBEInt<uint32_t>();
      value_type t{};
      accum += 4 + read(buffer, t, entry_len);
      value.push_back(std::move(t));
    }
    n += accum;
  } else {
    size_t accum = 0;
    while (accum < limit - n) {
      value_type t{};
      accum += read(buffer, t, limit - n - accum);
      value.push_back(std::move(t));
    }
    n += accum;
  }
  if (Opt & ListSizePrefixed && value.size() != list_len) {
    throw EnvoyException(
        fmt::format("decoded list size {} does not match expected size {}", value.size(), list_len));
  }
  return n;
}

// write function for fields of list types
template <EncodingOptions Opt, typename T>
  requires Writer<typename T::value_type>
std::enable_if_t<(is_vector<T>::value && !std::is_same_v<T, bytes>), size_t>
write_opt(Envoy::Buffer::Instance& buffer, const T& value) {
  size_t n = 0;
  if constexpr (Opt & ListSizePrefixed) {
    buffer.writeBEInt<uint32_t>(value.size());
    n += 4;
  } else if constexpr (Opt & ListLengthPrefixed) {
    uint32_t sum = 0;
    for (const auto& elem : value) {
      sum += elem.size();
    }
    if constexpr (Opt & CommaDelimited) {
      if (value.size() > 0) {
        sum += value.size() - 1; // commas
      }
    } else if constexpr (Opt & LengthPrefixed) {
      sum += 4 * value.size(); // size prefixes
    }
    buffer.writeBEInt<uint32_t>(sum);
    n += 4;
  }
  if constexpr (Opt & CommaDelimited) {
    for (size_t i = 0; i < value.size(); i++) {
      n += write(buffer, value.at(i));
      if (i < value.size() - 1) {
        buffer.writeByte(',');
        n += 1;
      }
    }
  } else if constexpr (Opt & LengthPrefixed) {
    Envoy::Buffer::OwnedImpl tmp;
    for (size_t i = 0; i < value.size(); i++) {
      n += 4 + write(tmp, value.at(i));
      buffer.writeBEInt<uint32_t>(tmp.length());
      buffer.move(tmp);
    }
  } else {
    for (Writer auto const& entry : value) {
      n += write(buffer, entry);
    }
  }
  return n;
}

} // namespace wire

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec