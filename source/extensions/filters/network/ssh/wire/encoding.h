#pragma once

#include "source/common/span.h"
#include "source/common/types.h"
#include "source/common/concepts.h"
#include "source/common/math.h"
#include "source/common/type_traits.h"
#include "source/common/visit.h"
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string>
#include <utility>

#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h"
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/validation.h"

namespace wire {

template <typename T>
concept Encoder = requires(T t) {
  // looks like: absl::StatusOr<size_t> encode(Envoy::Buffer::Instance&) const noexcept
  { t.encode(std::declval<Envoy::Buffer::Instance&>()) } noexcept -> std::same_as<absl::StatusOr<size_t>>;
};

template <typename T>
concept Decoder = requires(T t) {
  // looks like: absl::StatusOr<size_t> decode(Envoy::Buffer::Instance&, size_t) noexcept
  { t.decode(std::declval<Envoy::Buffer::Instance&>(), size_t{}) } noexcept -> std::same_as<absl::StatusOr<size_t>>;
};

// equivalent to sshbuf_put_bignum2_bytes
size_t writeBignum(Envoy::Buffer::Instance& buffer, std::span<const uint8_t> in);

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
size_t read(Envoy::Buffer::Instance& buffer, bool& t, size_t limit);
size_t write(Envoy::Buffer::Instance& buffer, const bool& t);

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
  return static_cast<EncodingOptions>(std::to_underlying(lhs) | std::to_underlying(rhs));
}

consteval EncodingOptions operator&(EncodingOptions lhs, EncodingOptions rhs) {
  return static_cast<EncodingOptions>(std::to_underlying(lhs) & std::to_underlying(rhs));
}

consteval EncodingOptions operator~(EncodingOptions opt) {
  return static_cast<EncodingOptions>(~std::to_underlying(opt));
}

// the functions below are only used for compile-time checks
namespace detail {
// asserts that the actual encoding options are a subset of the supported encoding options.
template <EncodingOptions Supported, EncodingOptions Opt>
consteval void check_supported_options() {
  static_assert((Opt & Supported) == Opt, "unsupported options");
}

template <EncodingOptions Incompatible, EncodingOptions Opt>
consteval void check_incompatible_options() {
  static_assert((Opt & Incompatible) != Incompatible, "incompatible options");
}
} // namespace detail

// read_opt is a wrapper around read() that supports additional encoding options.
// This specialization handles non-list types as well as strings and 'bytes' (vector<uint8_t>).
template <EncodingOptions Opt, typename T>
  requires (!is_vector_v<T> || is_bytes_v<T>)
size_t read_opt(Envoy::Buffer::Instance& buffer, T& value, explicit_size_t auto limit) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<LengthPrefixed, Opt>();

  if (limit == 0) {
    if constexpr (Opt & (LengthPrefixed | ListSizePrefixed | ListLengthPrefixed)) {
      throw Envoy::EnvoyException("short read");
    } else {
      return 0;
    }
  }
  if (buffer.length() < limit) [[unlikely]] {
    throw Envoy::EnvoyException("short read");
  }
  if constexpr (Opt & LengthPrefixed) {
    uint32_t entry_len = buffer.drainBEInt<uint32_t>();
    // Invariant: read<SshStringType>(buffer, value, N) always returns N (or throws an exception)
    return sizeof(uint32_t) + read(buffer, value, entry_len);
  } else {
    return read(buffer, value, limit);
  }
}

// write_opt is a wrapper around write() that supports additional encoding options.
// This specialization handles non-list types as well as strings and 'bytes' (vector<uint8_t>).
template <EncodingOptions Opt, typename T>
  requires (!is_vector_v<T> || is_bytes_v<T>)
size_t write_opt(Envoy::Buffer::Instance& buffer, const T& value) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<LengthPrefixed, Opt>();

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
           (is_vector_v<T> && !is_bytes_v<T>)
size_t read_opt(Envoy::Buffer::Instance& buffer, T& value, size_t limit) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<(CommaDelimited | LengthPrefixed | ListSizePrefixed | ListLengthPrefixed), Opt>();
  detail::check_incompatible_options<(CommaDelimited | LengthPrefixed), Opt>();
  detail::check_incompatible_options<(ListSizePrefixed | ListLengthPrefixed), Opt>();

  if (limit == 0) {
    if constexpr (Opt & (LengthPrefixed | ListSizePrefixed | ListLengthPrefixed)) {
      throw Envoy::EnvoyException("short read");
    } else {
      return 0;
    }
  }
  if (buffer.length() < limit) {
    throw Envoy::EnvoyException("short read");
  }
  using value_type = typename T::value_type;
  uint32_t list_size{};
  size_t n = 0;
  if constexpr (Opt & ListSizePrefixed) {
    list_size = buffer.drainBEInt<uint32_t>();
    limit = sub_sat(limit, sizeof(uint32_t));
    n += sizeof(uint32_t);
    if (list_size == 0) {
      return n;
    }
    if constexpr (Opt & CommaDelimited) {
      if (limit < 2 * list_size - 1) {
        throw Envoy::EnvoyException("invalid list size");
      }
    } else if constexpr (Opt & LengthPrefixed) {
      if (list_size > limit / 4) {
        throw Envoy::EnvoyException("invalid list size");
      }
    }
  } else if constexpr (Opt & ListLengthPrefixed) {
    auto len = buffer.drainBEInt<uint32_t>();
    limit = sub_sat(limit, sizeof(uint32_t));
    n += sizeof(uint32_t);
    if (len == 0) {
      return n;
    }
    if (buffer.length() < len) {
      throw Envoy::EnvoyException("invalid list length");
    }
    limit = std::min(limit, static_cast<size_t>(len));
  }
  if constexpr (Opt & CommaDelimited) {
    size_t accum = 0;
    auto view = linearizeToSpan(buffer).first(limit);
    for (size_t i = 0; i < limit; i++) {
      if (view[accum] != ',') {
        ++accum;
        continue;
      }

      // RFC4251 § 5
      if (accum == 0 || i == limit - 1) {
        throw Envoy::EnvoyException("invalid empty string in comma-separated list");
      } else if (view[accum - 1] == 0) {
        throw Envoy::EnvoyException("invalid null-terminated string in comma-separated list");
      }

      value_type t{};
      auto nread = read(buffer, t, accum);
      SECURITY_ASSERT(nread == accum, "buffer concurrent modification detected");
      value.push_back(std::move(t));
      accum = 0;
      n += nread;
      if constexpr (Opt & ListSizePrefixed) {
        if (value.size() == list_size) {
          // read exactly the number of elements needed, don't read anything else
          return n;
        }
      }
      buffer.drain(1); // skip the ',' byte (index i)
      n += 1;
      view = view.subspan(nread + 1);
    }
    ASSERT(accum > 0);
    if (view[accum - 1] == 0) {
      throw Envoy::EnvoyException("invalid null-terminated string in comma-separated list");
    }
    value_type t{};
    auto nread = read(buffer, t, accum);
    SECURITY_ASSERT(nread == accum, "buffer concurrent modification detected");
    n += nread;
    // limit isn't used after this
    value.push_back(std::move(t));
  } else {
    while (limit > 0) {
      if constexpr (Opt & ListSizePrefixed) {
        if (value.size() == list_size) {
          break;
        }
      }
      size_t value_read_limit = limit;
      if constexpr (Opt & LengthPrefixed) {
        value_read_limit = static_cast<size_t>(buffer.drainBEInt<uint32_t>());
        limit = sub_sat(limit, sizeof(uint32_t));
        n += sizeof(uint32_t);
      }
      value_type t{};
      size_t nread = read(buffer, t, value_read_limit);
      if constexpr (Opt & LengthPrefixed) {
        if (nread != value_read_limit) {
          throw Envoy::EnvoyException("short read in list element");
        }
      }
      limit = sub_sat(limit, nread);
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
           (is_vector_v<T> && !is_bytes_v<T>)
size_t write_opt(Envoy::Buffer::Instance& buffer, const T& value) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<(CommaDelimited | LengthPrefixed | ListSizePrefixed | ListLengthPrefixed), Opt>();
  detail::check_incompatible_options<(CommaDelimited | LengthPrefixed), Opt>();
  detail::check_incompatible_options<(CommaDelimited | ListSizePrefixed), Opt>();
  detail::check_incompatible_options<(ListSizePrefixed | ListLengthPrefixed), Opt>();

  size_t total = 0;
  if constexpr (Opt & ListSizePrefixed) {
    buffer.writeBEInt(static_cast<uint32_t>(value.size()));
    total += sizeof(uint32_t);
  } else if constexpr (Opt & ListLengthPrefixed) {
    uint32_t len = 0;
    for (const auto& elem : value) {
      if constexpr (requires { std::size(elem); }) {
        // if std::size is available, use it
        len += std::size(elem);
      } else {
        // otherwise fall back to sizeof (for integer/enum types)
        len += sizeof(elem);
      }
    }
    if constexpr (Opt & CommaDelimited) {
      if (value.size() > 0) {
        len += value.size() - 1; // commas
      }
    } else if constexpr (Opt & LengthPrefixed) {
      len += sizeof(uint32_t) * value.size(); // size prefixes
    }
    buffer.writeBEInt(static_cast<uint32_t>(len));
    total += sizeof(uint32_t);
  }
  if constexpr (Opt & CommaDelimited) {
    for (size_t i = 0; i < value.size(); i++) {
      auto n = write(buffer, value.at(i));
      if (n == 0) [[unlikely]] {
        throw Envoy::EnvoyException("invalid empty string in comma-separated list");
      }
      total += n;
      if (i < value.size() - 1) {
        buffer.writeByte(',');
        total += 1;
      }
    }
  } else if constexpr (Opt & LengthPrefixed) {
    Envoy::Buffer::OwnedImpl tmp;
    for (const auto& elem : value) {
      total += sizeof(uint32_t) + write(tmp, elem);
      buffer.writeBEInt(static_cast<uint32_t>(tmp.length()));
      buffer.move(tmp);
    }
  } else {
    for (Writer auto const& entry : value) {
      total += write(buffer, entry);
    }
  }
  return total;
}

// Utility function to decode a list of Decoder objects in order. The size passed to each Decoder's
// decode method will be adjusted after each is read. Returns the total number of bytes read.
template <Decoder... Args>
  requires (sizeof...(Args) > 0)
absl::StatusOr<size_t> decodeSequence(Envoy::Buffer::Instance& buffer, explicit_size_t auto limit, Args&&... args) noexcept {
  if constexpr (!contains_tag_no_validation<Args...>) {
    detail::check_sub_message_field_order<Args...>();
  }

  if (buffer.length() < limit) {
    return absl::InvalidArgumentError("short read");
  }
  size_t n = 0;
  absl::Status stat{};

  auto decodeOne = [&](Decoder auto&& field) -> bool {
    if constexpr (is_tag_no_validation<decltype(field)>) {
      return true;
    } else {
      // NB: (limit-n) is allowed to be zero here
      auto r = field.decode(buffer, limit - n);
      if (!r.ok()) {
        stat = r.status();
        return false;
      }
      ASSERT(*r <= limit - n, "decode() returned value >= limit");
      n += *r;
      return true;
    }
  };

  // This fold expression calls decodeOne for each field, and stops if decodeOne returns false.
  (void)(decodeOne(std::forward<Args>(args)) && ...);

  // stat and n are updated from within decodeOne
  if (!stat.ok()) {
    return stat;
  }
  return n;
}

inline absl::StatusOr<size_t> decodeSequence(Envoy::Buffer::Instance&, explicit_size_t auto) {
  return 0;
}

// Utility function to encode a list of Encoder objects in order. Returns the total number of bytes
// written.
template <Encoder... Args>
  requires (sizeof...(Args) > 0)
absl::StatusOr<size_t> encodeSequence(Envoy::Buffer::Instance& buffer, const Args&... args) noexcept {
  if constexpr (!contains_tag_no_validation<Args...>) {
    detail::check_sub_message_field_order<Args...>();
  }

  size_t n = 0;
  absl::Status stat{};

  auto encodeOne = [&](Encoder auto& field) -> bool {
    if constexpr (is_tag_no_validation<decltype(field)>) {
      return true;
    } else {
      auto r = field.encode(buffer);
      if (!r.ok()) [[unlikely]] {
        stat = r.status();
        return false;
      }
      n += *r;
      if (n < MaxPacketSize) [[likely]] {
        return true;
      } else {
        stat = absl::AbortedError("message size too large");
        return false;
      }
    }
  };

  // This fold expression calls encodeOne for each field, and stops if encodeOne returns false.
  (void)(encodeOne(args) && ...);

  // stat and n are updated from within encodeOne
  if (!stat.ok()) {
    return stat;
  }
  return n;
}

absl::StatusOr<size_t> encodeSequence(Envoy::Buffer::Instance&);

} // namespace wire
