#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string>
#include <type_traits>
#include <utility>

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace wire {

template <typename T>
concept Encoder = requires(T t) {
  // looks like: absl::StatusOr<size_t> encode(Envoy::Buffer::Instance&) noexcept
  { t.encode(std::declval<Envoy::Buffer::Instance&>()) } noexcept -> std::same_as<absl::StatusOr<size_t>>;
};

template <typename T>
concept Decoder = requires(T t) {
  // looks like: absl::StatusOr<size_t> decode(Envoy::Buffer::Instance&, size_t) noexcept
  { t.decode(std::declval<Envoy::Buffer::Instance&>(), size_t{}) } noexcept -> std::same_as<absl::StatusOr<size_t>>;
};

// equivalent to sshbuf_put_bignum2_bytes
inline size_t writeBignum(Envoy::Buffer::Instance& buffer, std::span<const uint8_t> in) {
  // skip leading zeros
  in = in.subspan(std::distance(in.begin(),
                                std::find_if(in.begin(), in.end(),
                                             [](const uint8_t& b) { return b != 0; })));
  size_t in_size = in.size();
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

template <SshStringType T>
[[nodiscard]] T flushTo(Envoy::Buffer::Instance& buf, size_t n) {
  ASSERT(n <= buf.length());
  T out;
  out.resize(n);
  buf.copyOut(0, n, out.data());
  buf.drain(n);
  return out;
}

template <SshStringType T>
[[nodiscard]] T flushTo(Envoy::Buffer::Instance& buf) {
  return flushTo<T>(buf, buf.length());
}

template <SshStringType T>
void flushTo(Envoy::Buffer::Instance& buf, T& out, size_t n) {
  ASSERT(n <= buf.length());
  out.resize(n);
  buf.copyOut(0, n, out.data());
  buf.drain(n);
}

template <SshStringType T>
void flushTo(Envoy::Buffer::Instance& buf, T& out) {
  flushTo(buf, out, buf.length());
}

template <SshStringType T>
absl::StatusOr<T> encodeTo(Encoder auto& encoder) {
  Envoy::Buffer::OwnedImpl tmp;
  auto r = encoder.encode(tmp);
  if (!r.ok()) {
    return r.status();
  }
  return flushTo<T>(tmp);
}

template <SshStringType T>
absl::StatusOr<size_t> encodeTo(Encoder auto& encoder, T& out) {
  Envoy::Buffer::OwnedImpl tmp;
  auto r = encoder.encode(tmp);
  if (!r.ok()) {
    return r.status();
  }
  flushTo<T>(tmp, out);
  return *r;
}

// Reads a single typed value, draining at most 'limit' bytes from the buffer. Returns the actual
// number of bytes read, which can be <= limit. Throws an exception if `buffer.length() < limit`.
template <typename T>
size_t read(Envoy::Buffer::Instance& buffer, T& t, size_t limit) = delete;

// Writes a single typed value to the buffer. Returns the number of bytes written.
template <typename T>
size_t write(Envoy::Buffer::Instance& buffer, const T& t) = delete;

// read/write integer types
template <SshIntegerType T>
size_t read(Envoy::Buffer::Instance& buffer, T& t, size_t limit) {
  if (limit == 0 || buffer.length() < limit) {
    // zero-length integral types are not allowed
    throw Envoy::EnvoyException("short read");
  }
  t = buffer.drainBEInt<T>();
  return sizeof(T);
}
template <SshIntegerType T>
size_t write(Envoy::Buffer::Instance& buffer, const T& t) {
  buffer.writeBEInt(t);
  return sizeof(T);
}

// read/write bool
inline size_t read(Envoy::Buffer::Instance& buffer, bool& t, size_t limit) {
  if (limit == 0 || buffer.length() < limit) {
    // zero-length integral types are not allowed
    throw Envoy::EnvoyException("short read");
  }
  t = buffer.drainBEInt<uint8_t>() != 0;
  return sizeof(t);
}
inline size_t write(Envoy::Buffer::Instance& buffer, const bool& t) {
  buffer.writeByte<uint8_t>(t ? 1 : 0);
  return sizeof(t);
}

// read/write string types
template <SshStringType T>
size_t read(Envoy::Buffer::Instance& buffer, T& t, size_t limit) {
  if (limit == 0) {
    return 0; // zero-length strings are allowed
  }
  if (buffer.length() < limit) {
    throw Envoy::EnvoyException("short read");
  }
  t.resize(limit);
  buffer.copyOut(0, limit, t.data());
  buffer.drain(limit);
  return limit;
}
template <SshStringType T>
size_t write(Envoy::Buffer::Instance& buffer, const T& t) {
  buffer.add(t.data(), t.size());
  return t.size();
}

// read/write arrays
template <size_t N>
size_t read(Envoy::Buffer::Instance& buffer, fixed_bytes<N>& t, size_t limit) {
  if (limit < N) {
    throw Envoy::EnvoyException("incomplete read into fixed-size array");
  }
  if (buffer.length() < N) {
    throw Envoy::EnvoyException("short read");
  }
  buffer.copyOut(0, N, t.data());
  buffer.drain(N);
  return N;
}
template <size_t N>
size_t write(Envoy::Buffer::Instance& buffer, const fixed_bytes<N>& t) {
  buffer.add(t.data(), t.size());
  return N;
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

  NameListFormat = CommaDelimited | ListLengthPrefixed,
};

consteval EncodingOptions operator|(EncodingOptions lhs, EncodingOptions rhs) {
  return static_cast<EncodingOptions>(
    static_cast<std::underlying_type_t<EncodingOptions>>(lhs) |
    static_cast<std::underlying_type_t<EncodingOptions>>(rhs));
}

consteval EncodingOptions operator&(EncodingOptions lhs, EncodingOptions rhs) {
  return static_cast<EncodingOptions>(
    static_cast<std::underlying_type_t<EncodingOptions>>(lhs) &
    static_cast<std::underlying_type_t<EncodingOptions>>(rhs));
}

consteval EncodingOptions operator~(EncodingOptions opt) {
  return static_cast<EncodingOptions>(~static_cast<std::underlying_type_t<EncodingOptions>>(opt));
}

// asserts that the actual encoding options are a subset of the supported encoding options.
template <EncodingOptions Supported, EncodingOptions Opt>
constexpr void check_supported_options() {
  static_assert((Opt & Supported) == Opt, "unsupported options");
}

template <EncodingOptions Incompatible, EncodingOptions Opt>
constexpr void check_incompatible_options() {
  static_assert((Opt & Incompatible) != Incompatible, "incompatible options");
}

// read_opt is a wrapper around read() that supports additional encoding options.
// This specialization handles non-list types as well as strings and 'bytes' (vector<uint8_t>).
template <EncodingOptions Opt, typename T>
  requires (!is_vector<T>::value || std::is_same_v<T, bytes>)
size_t read_opt(Envoy::Buffer::Instance& buffer, T& value, explicit_size_t auto limit) { // NOLINT
  check_supported_options<LengthPrefixed, Opt>();
  if (limit == 0) {
    return 0;
  }
  if (buffer.length() < limit) {
    throw Envoy::EnvoyException("short read");
  }
  if constexpr (Opt & LengthPrefixed) {
    uint32_t entry_len = buffer.drainBEInt<uint32_t>();
    auto nread = read(buffer, value, entry_len);
    if (nread != entry_len) [[unlikely]] {
      throw Envoy::EnvoyException("short read");
    }
    return 4 + entry_len;
  } else {
    return read(buffer, value, limit);
  }
}

// write_opt is a wrapper around write() that supports additional encoding options.
// This specialization handles non-list types as well as strings and 'bytes' (vector<uint8_t>).
template <EncodingOptions Opt, typename T>
  requires (!is_vector<T>::value || std::is_same_v<T, bytes>)
size_t write_opt(Envoy::Buffer::Instance& buffer, const T& value) { // NOLINT
  check_supported_options<LengthPrefixed, Opt>();
  if constexpr (Opt & LengthPrefixed) {
    Envoy::Buffer::OwnedImpl tmp;
    auto size = write(tmp, value);
    buffer.writeBEInt(static_cast<uint32_t>(size));
    buffer.move(tmp);
    return 4 + size;
  } else {
    return write(buffer, value);
  }
}

// This specialization of read_opt handles list types (not including strings).
// The following encoding options can be used:
// - ListSizePrefixed: if set, prepends a uint32 containing the number of elements in the list.
// - ListLengthPrefixed: if set, prepends a uint32 containing the total length of all elements
//   in the list, plus any delimiters between list elements.
// - CommaDelimited: if set, elements in the list are separated with a ',' character. This option
//   cannot be used together with LengthPrefixed.
// - LengthPrefixed: if set, each element will be preceded by a uint32 containing that element's
//   length. This option cannot be used together with CommaDelimited.
template <EncodingOptions Opt, typename T>
  requires Reader<typename T::value_type> &&
           (is_vector<T>::value && !std::is_same_v<T, bytes>)
size_t read_opt(Envoy::Buffer::Instance& buffer, T& value, size_t limit) { // NOLINT
  check_supported_options<(CommaDelimited | LengthPrefixed | ListSizePrefixed | ListLengthPrefixed), Opt>();
  check_incompatible_options<(CommaDelimited | LengthPrefixed), Opt>();
  check_incompatible_options<(CommaDelimited | ListSizePrefixed), Opt>();

  if (limit == 0) {
    return 0;
  }
  if (buffer.length() < limit) {
    throw Envoy::EnvoyException("short read");
  }
  using value_type = typename T::value_type;
  uint32_t list_size{};
  size_t n = 0;
  if constexpr (Opt & ListSizePrefixed) {
    list_size = buffer.drainBEInt<uint32_t>();
    n += 4;
    if (list_size == 0) {
      return n;
    }
    if constexpr (Opt & CommaDelimited) {
      if (list_size > (limit - n) / 2 - 1) {
        throw Envoy::EnvoyException("invalid list size");
      }
    } else if constexpr (Opt & LengthPrefixed) {
      if (list_size > (limit - n) / 4) {
        throw Envoy::EnvoyException("invalid list size");
      }
    }
  } else if constexpr (Opt & ListLengthPrefixed) {
    auto len = buffer.drainBEInt<uint32_t>();
    n += 4;
    if (len == 0) {
      return n;
    }
    if (buffer.length() < len) {
      throw Envoy::EnvoyException("invalid list length");
    }
    limit = len + n;
  }
  if constexpr (Opt & CommaDelimited) {
    size_t value_read_limit = limit - n;
    ASSERT(value_read_limit > 0);
    size_t accum = 0;
    for (size_t i = 0; i < value_read_limit; i++) {
      char c = buffer.peekInt<char>(accum);
      if (c != ',') {
        ++accum;
        continue;
      }

      // RFC4251 § 5
      if (accum == 0 || i == value_read_limit - 1) {
        throw Envoy::EnvoyException("invalid empty string in comma-separated list");
      } else if (buffer.peekInt<char>(accum - 1) == 0) {
        throw Envoy::EnvoyException("invalid null-terminated string in comma-separated list");
      }

      value_type t{};
      auto nread = read(buffer, t, accum);
      SECURITY_ASSERT(nread == accum, "buffer concurrent modification detected");
      value.push_back(std::move(t));
      accum = 0;
      buffer.drain(1); // skip the ',' byte (index i)
    }
    ASSERT(accum > 0);
    if (buffer.peekInt<char>(accum - 1) == 0) {
      throw Envoy::EnvoyException("invalid null-terminated string in comma-separated list");
    }
    value_type t{};
    auto nread = read(buffer, t, accum);
    SECURITY_ASSERT(nread == accum, "buffer concurrent modification detected");
    value.push_back(std::move(t));
    n += value_read_limit;
  } else {
    while (limit - n > 0) {
      if constexpr (Opt & ListSizePrefixed) {
        if (value.size() == list_size) {
          break;
        }
      }
      size_t value_read_limit = limit - n;
      if constexpr (Opt & LengthPrefixed) {
        value_read_limit = static_cast<size_t>(buffer.drainBEInt<uint32_t>());
        n += 4;
      }
      value_type t{};
      size_t nread = read(buffer, t, value_read_limit);
      if constexpr (Opt & LengthPrefixed) {
        if (nread != value_read_limit) {
          throw Envoy::EnvoyException("short read in list element");
        }
      }
      n += nread;
      value.push_back(std::move(t));
    }
  }
  if (Opt & ListSizePrefixed && value.size() != list_size) {
    throw Envoy::EnvoyException(
      fmt::format("decoded list size {} does not match expected size {}", value.size(), list_size));
  }
  return n;
}

// write function for fields of list types
template <EncodingOptions Opt, typename T>
  requires Writer<typename T::value_type> &&
           (is_vector<T>::value && !std::is_same_v<T, bytes>)
size_t write_opt(Envoy::Buffer::Instance& buffer, const T& value) { // NOLINT
  check_supported_options<(CommaDelimited | LengthPrefixed | ListSizePrefixed | ListLengthPrefixed), Opt>();
  check_incompatible_options<(CommaDelimited | LengthPrefixed), Opt>();
  check_incompatible_options<(CommaDelimited | ListSizePrefixed), Opt>();

  size_t n = 0;
  if constexpr (Opt & ListSizePrefixed) {
    buffer.writeBEInt(static_cast<uint32_t>(value.size()));
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
    buffer.writeBEInt(static_cast<uint32_t>(sum));
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
      buffer.writeBEInt(static_cast<uint32_t>(tmp.length()));
      buffer.move(tmp);
    }
  } else {
    for (Writer auto const& entry : value) {
      n += write(buffer, entry);
    }
  }
  return n;
}

template <typename T>
struct is_sub_message : std::false_type {};

template <ssize_t I, ssize_t K>
struct sub_message_index_t {
  static constexpr ssize_t index = I;
  static constexpr ssize_t key_field_index = K;
};

template <typename T, typename... Args>
consteval ssize_t key_field_index() {
  if constexpr (is_sub_message<T>::value) {
    static constexpr auto list = {std::is_same_v<std::decay_t<typename T::key_field_type>, std::decay_t<Args>>...};
    constexpr auto it = std::find(list.begin(), list.end(), true);
    return it == list.end() ? -1 : std::distance(list.begin(), it);
  }
  return -1;
}

template <typename... Args>
consteval auto sub_message_index() {
  static constexpr std::array<bool, sizeof...(Args)> list = {is_sub_message<std::decay_t<Args>>::value...};
  static constexpr std::array<ssize_t, sizeof...(Args)> key_list = {key_field_index<std::decay_t<Args>, std::decay_t<Args>...>()...};
  static_assert(list.size() == key_list.size());
  static constexpr auto it = std::find(list.begin(), list.end(), true);
  if constexpr (it == list.end()) {
    return sub_message_index_t<-1, -1>{};
  } else {
    static constexpr ssize_t index = std::distance(list.begin(), it);
    static constexpr ssize_t key_entry = key_list.at(index);
    return sub_message_index_t<index, key_entry>{};
  }
}

// Utility function to decode a list of Decoder objects in order. The size passed to each Decoder's
// decode method will be adjusted after each is read. Returns the total number of bytes read.
template <Decoder... Args>
absl::StatusOr<size_t> decodeSequence(Envoy::Buffer::Instance& buffer, explicit_size_t auto limit, Args&&... args) noexcept {
  if constexpr (auto idx = sub_message_index<std::decay_t<Args>...>(); idx.index != -1z) {
    static_assert(idx.key_field_index >= 0z && idx.key_field_index < idx.index,
                  "must decode key_field before corresponding sub_message");
  }

  if (buffer.length() < limit) {
    return absl::InvalidArgumentError("short read");
  }
  size_t n = 0;
  absl::Status stat{};

  auto decodeOne = [&](Decoder auto&& field) -> bool {
    // NB: (limit-n) is allowed to be zero here
    auto r = field.decode(buffer, limit - n);
    if (!r.ok()) {
      stat = r.status();
      return false;
    }
    SECURITY_ASSERT(*r <= limit - n, "decode() returned value >= limit");
    n += *r;
    return true;
  };

  // This fold expression calls decodeOne for each field, and stops if decodeOne returns false.
  (void)(decodeOne(std::forward<Args>(args)) && ...);

  // stat and n are updated from within decodeOne
  if (!stat.ok()) {
    return stat;
  }
  return n;
}

// Utility function to encode a list of Encoder objects in order. Returns the total number of bytes
// written.
template <Encoder... Args>
absl::StatusOr<size_t> encodeSequence(Envoy::Buffer::Instance& buffer, const Args&... args) noexcept {
  if constexpr (auto idx = sub_message_index<std::decay_t<Args>...>(); idx.index != -1z) {
    static_assert(idx.key_field_index >= 0z && idx.key_field_index < idx.index,
                  "must encode key_field before corresponding sub_message");
  }

  size_t n = 0;
  absl::Status stat{};

  auto encodeOne = [&](Encoder auto& field) -> bool {
    auto r = field.encode(buffer);
    if (!r.ok()) {
      stat = r.status();
      return false;
    }
    n += *r;
    return true;
  };

  // This fold expression calls encodeOne for each field, and stops if encodeOne returns false.
  (void)(encodeOne(args) && ...);

  // stat and n are updated from within encodeOne
  if (!stat.ok()) {
    return stat;
  }
  return n;
}

} // namespace wire
