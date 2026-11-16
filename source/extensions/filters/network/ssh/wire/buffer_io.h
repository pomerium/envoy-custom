#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end

#include "source/common/concepts.h"
#include "source/common/math.h"
#include "source/common/span.h"
#include "source/common/type_traits.h"
#include "source/common/types.h"

#include "source/extensions/filters/network/ssh/wire/common.h"

namespace wire {

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

// Buffer utils

template <SshStringType T>
void flushTo(Envoy::Buffer::Instance& buf, T& out, size_t n) {
  ASSERT(n <= buf.length());
  out.resize(n);
  buf.copyOut(0, n, out.data());
  buf.drain(n);
}

template <SshStringType T>
[[nodiscard]] T flushTo(Envoy::Buffer::Instance& buf, size_t n) {
  T out;
  flushTo(buf, out, n);
  return out;
}

template <SshStringType T>
[[nodiscard]] T flushTo(Envoy::Buffer::Instance& buf) {
  return flushTo<T>(buf, buf.length());
}

template <SshStringType T>
void flushTo(Envoy::Buffer::Instance& buf, T& out) {
  flushTo(buf, out, buf.length());
}

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

template <typename T>
constexpr size_t size_or_sizeof(const T& t) {
  if constexpr (requires { std::size(t); }) {
    // if std::size is available, use it
    return std::size(t);
  } else if constexpr (std::integral<T>) {
    // otherwise fall back to sizeof (for integer/enum types)
    return sizeof(t);
  }
}
} // namespace detail

template <EncodingOptions Opt, typename T>
  requires ((Opt & EncodingOptions::Omit) != 0)
size_t read_opt(Envoy::Buffer::Instance&, T&, explicit_size_t auto) { // NOLINT(readability-identifier-naming)
  static_assert(Opt == EncodingOptions::Omit, "Omit cannot be used with other encoding options");
  return 0;
}

// read_opt is a wrapper around read() that supports additional encoding options.
// This specialization handles non-list types as well as strings and 'bytes' (vector<uint8_t>).
template <EncodingOptions Opt, typename T>
  requires (!is_vector_v<T> || is_bytes_v<T>) &&
           ((Opt & EncodingOptions::Omit) == 0)
size_t read_opt(Envoy::Buffer::Instance& buffer, T& value, explicit_size_t auto limit) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<LengthPrefixed, Opt>();

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
  if constexpr (Opt & LengthPrefixed) {
    uint32_t entry_len = buffer.drainBEInt<uint32_t>();
    if (sub_sat(limit, sizeof(uint32_t)) < entry_len) {
      throw Envoy::EnvoyException("short read");
    }
    // Invariant: read<SshStringType>(buffer, value, N) always returns N (or throws an exception)
    return sizeof(uint32_t) + read(buffer, value, entry_len);
  } else {
    return read(buffer, value, limit);
  }
}

template <EncodingOptions Opt, typename T>
  requires ((Opt & EncodingOptions::Omit) != 0)
size_t write_opt(Envoy::Buffer::Instance&, const T&) { // NOLINT(readability-identifier-naming)
  static_assert(Opt == EncodingOptions::Omit, "Omit cannot be used with other encoding options");
  return 0;
}

// write_opt is a wrapper around write() that supports additional encoding options.
// This specialization handles non-list types as well as strings and 'bytes' (vector<uint8_t>).
template <EncodingOptions Opt, typename T>
  requires (!is_vector_v<T> || is_bytes_v<T>) &&
           ((Opt & EncodingOptions::Omit) == 0)
size_t write_opt(Envoy::Buffer::Instance& buffer, const T& value) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<LengthPrefixed, Opt>();

  if constexpr (Opt & LengthPrefixed) {
    const auto size = detail::size_or_sizeof(value);
    buffer.writeBEInt(static_cast<uint32_t>(size));
    auto n = write(buffer, value);
    ASSERT(size == n);
    return n + 4;
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
           (is_vector_v<T> && !is_bytes_v<T>) &&
           ((Opt & EncodingOptions::Omit) == 0)
size_t read_opt(Envoy::Buffer::Instance& buffer, T& value, size_t limit) { // NOLINT(readability-identifier-naming)
  detail::check_supported_options<(CommaDelimited | LengthPrefixed | ListSizePrefixed | ListLengthPrefixed), Opt>();
  detail::check_incompatible_options<(CommaDelimited | LengthPrefixed), Opt>();
  detail::check_incompatible_options<(CommaDelimited | ListSizePrefixed), Opt>();
  detail::check_incompatible_options<(ListSizePrefixed | ListLengthPrefixed), Opt>();

  if (limit == 0) {
    // A list with LengthPrefixed elements can read 0 bytes (an empty list), but if the list itself
    // needs a length or size prefix, it is required.
    if constexpr (Opt & (ListSizePrefixed | ListLengthPrefixed)) {
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

      // RFC4251 § 5, 'name-list' format:
      //  Terminating null characters MUST NOT be used, neither
      //  for the individual names, nor for the list as a whole.
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
      buffer.drain(1); // skip the ',' byte (index i)
      n += nread + 1;
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
           (is_vector_v<T> && !is_bytes_v<T>) &&
           ((Opt & EncodingOptions::Omit) == 0)
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
      if (n == 0) {
        throw Envoy::EnvoyException("invalid empty string in comma-separated list");
      }
      total += n;
      if (i < value.size() - 1) {
        buffer.writeByte(',');
        total += 1;
      }
    }
  } else if constexpr (Opt & LengthPrefixed) {
    for (const auto& elem : value) {
      total += write_opt<LengthPrefixed>(buffer, elem);
    }
  } else {
    for (Writer auto const& entry : value) {
      total += write(buffer, entry);
    }
  }
  return total;
}

// equivalent to sshbuf_put_bignum2_bytes
size_t writeBignum(Envoy::Buffer::Instance& buffer, std::span<const uint8_t> in);

} // namespace wire