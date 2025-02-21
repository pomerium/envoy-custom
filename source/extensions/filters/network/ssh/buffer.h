#pragma once

#include <concepts>
#include <cstdint>
#include <algorithm>
#include <string>
#include <tuple>
#include <type_traits>
#include <variant>

#include "source/common/buffer/buffer_impl.h"

#include "source/extensions/filters/network/ssh/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum class SshMessageType : uint8_t;

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
concept encoder = requires(T t) {
  { t.encode(std::declval<Envoy::Buffer::Instance&>()) };
};

template <typename T>
concept decoder = requires(T t) {
  { t.decode(std::declval<Envoy::Buffer::Instance&>(), std::declval<size_t>()) };
};

template <typename T>
  requires encoder<T>
inline bytes encodeToBytes(const T& t) {
  Envoy::Buffer::OwnedImpl tmp;
  t.encode(tmp);
  return flushToBytes(tmp);
}

enum FieldOptions : uint32_t {
  None = 0,
  LengthPrefixed = 1 << 0,
  CommaDelimited = 1 << 1,
  ListSizePrefixed = 1 << 2,
  ListLengthPrefixed = 1 << 3,
  Conditional = 1 << 4,

  NameListFormat = CommaDelimited | ListLengthPrefixed,
};

constexpr inline FieldOptions operator|(FieldOptions lhs, FieldOptions rhs) {
  return static_cast<FieldOptions>(
      static_cast<std::underlying_type_t<FieldOptions>>(lhs) |
      static_cast<std::underlying_type_t<FieldOptions>>(rhs));
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

size_t read(Envoy::Buffer::Instance& buffer, encoder auto& list, size_t len) {
  size_t n = 0;
  while (n < len) {
    typename std::remove_cvref_t<decltype(list)>::value_type b;
    n += b.decode(buffer, len - n);
    if (n > len) {
      throw EnvoyException("list corrupted");
    }
    list.push_back(std::move(b));
  }
  return n;
}

inline size_t write(Envoy::Buffer::Instance& buffer, decoder auto& list) {
  size_t n = 0;
  for (const auto& b : list) {
    n += b.encode(buffer, b);
  }
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

template <typename T, FieldOptions Opt>
struct field_base {
  T value{};

  operator T() const& {
    return value;
  }

  operator T() & {
    return value;
  }

  T* operator->() {
    return &value;
  }

  const T* operator->() const {
    return &value;
  }

  T& operator*() {
    return value;
  }

  const T& operator*() const {
    return value;
  }

  auto operator[](int i) const {
    return value[i];
  }

  auto operator[](int i) {
    return value[i];
  }

  auto operator<=>(const field_base& other) const = default;
  bool operator==(const field_base& other) const = default;

  template <typename U>
  field_base& operator=(const U& rhs) {
    value = rhs;
    return *this;
  }

  template <typename U>
  field_base& operator=(U&& rhs) {
    value = std::forward<U>(rhs);
    return *this;
  }

  template <typename U>
  field_base& operator=(std::initializer_list<U> rhs) {
    value = rhs;
    return *this;
  }

  template <typename U>
  auto operator<=>(const U& other) const {
    return value <=> other;
  }

  template <typename U>
  bool operator==(const U& other) const {
    return value == other;
  }
};

template <typename T>
struct type_or_value_type : std::type_identity<T> {};

template <typename T, typename Allocator>
struct type_or_value_type<std::vector<T, Allocator>> : std::type_identity<T> {};

template <typename T>
using type_or_value_type_t = type_or_value_type<T>::type;

template <typename... Args>
using first_type_t = std::tuple_element_t<0, std::tuple<std::decay_t<Args>...>>;

template <typename T, FieldOptions Opt = None, typename = void>
  requires ReadWriter<type_or_value_type_t<T>>
struct field;

template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

// read function for standard field types
template <FieldOptions Opt, typename T>
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
template <FieldOptions Opt, typename T>
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
template <FieldOptions Opt, typename T>
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
template <FieldOptions Opt, typename T>
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

// normal field (not conditional)
template <typename T, FieldOptions Opt>
  requires ReadWriter<type_or_value_type_t<T>>
struct field<T, Opt, std::enable_if_t<(Opt & Conditional) == 0>> : field_base<T, Opt> {
  static_assert(sizeof(field_base<T, Opt>) == sizeof(T));
  using field_value_type = T;
  using field_base<T, Opt>::value;
  using field_base<T, Opt>::operator=;

  size_t decode(Envoy::Buffer::Instance& buffer, size_t n = 0) {
    return read_opt<Opt>(buffer, value, n);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const {
    return write_opt<Opt>(buffer, value);
  }
};

// conditional field
template <typename T, FieldOptions Opt>
  requires ReadWriter<type_or_value_type_t<T>>
struct field<T, Opt, std::enable_if_t<(Opt & Conditional) != 0>> : field_base<T, Opt> {
  static_assert(sizeof(field_base<T, Opt>) == sizeof(T));
  using field_value_type = T;
  using field_base<T, Opt>::value;
  using field_base<T, Opt>::operator=;

  auto enable_if(bool condition) const {
    return codec{
        .enabled = condition,
        .vp = const_cast<T*>(&value),
    };
  }

private:
  struct codec {
    bool enabled;
    T* vp;
    size_t decode(Envoy::Buffer::Instance& buffer, size_t n = 0) {
      if (!enabled) {
        return 0;
      }
      return read_opt<Opt>(buffer, *vp, n);
    }
    size_t encode(Envoy::Buffer::Instance& buffer) const {
      if (!enabled) {
        return 0;
      }
      return write_opt<Opt>(buffer, *vp);
    }
  };
};

template <typename... Fields>
size_t decodeFields(Envoy::Buffer::Instance& buffer, size_t limit, Fields&&... fields) {
  size_t n = 0;
  ([&] { n += fields.decode(buffer, limit - n); }(), ...);
  return n;
}

template <SshMessageType MT, typename... Fields>
size_t decodeMsg(Envoy::Buffer::Instance& buffer, size_t limit, Fields&&... fields) {
  if (auto mt = buffer.drainInt<SshMessageType>(); mt != MT) {
    throw EnvoyException(fmt::format("decoded unexpected message type {}, expected {}",
                                     static_cast<uint8_t>(mt),
                                     static_cast<uint8_t>(MT)));
  }
  return 1 + decodeFields(buffer, limit - 1, std::forward<Fields>(fields)...);
}

template <typename... Fields>
size_t encodeFields(Envoy::Buffer::Instance& buffer, const Fields&... fields) {
  size_t n = 0;
  ([&] { n += fields.encode(buffer); }(), ...);
  return n;
}

template <SshMessageType MT, typename... Fields>
size_t encodeMsg(Envoy::Buffer::Instance& buffer, const Fields&... fields) {
  buffer.writeByte(MT);
  return 1 + encodeFields(buffer, fields...);
}

// from https://en.cppreference.com/w/cpp/utility/variant/visit
template <typename... Ts>
struct overloads : Ts... {
  using Ts::operator()...;
};

template <typename... Options>
struct sub_message {
  std::variant<std::monostate, Options...> oneof;
  using field_value_type = decltype(oneof);
  static constexpr auto option_names = {Options::request_type...};
  static constexpr auto decoders =
      {+[](field_value_type& oneof, Envoy::Buffer::Instance& buffer, size_t limit) -> size_t {
        Options opt;
        size_t n = opt.decode(buffer, limit);
        oneof = std::move(opt);
        return n;
      }...};
  static constexpr auto encoders =
      {+[](const field_value_type& oneof, Envoy::Buffer::Instance& buffer) -> size_t {
        return std::get<Options>(oneof).encode(buffer);
      }...};

  template <typename T>
  sub_message& operator=(T&& other) {
    // set the object in the variant
    oneof = std::forward<T>(other);
    // update the key field
    key_field_->value = std::decay_t<T>::request_type;
    return *this;
  }

  template <typename T>
  decltype(auto) get() {
    return std::get<T>(oneof);
  }
  template <typename T>
  decltype(auto) get() const {
    return std::get<T>(oneof);
  }

  void set_key_field(field<std::string, LengthPrefixed>* field_ptr) {
    key_field_ = field_ptr;
  }

  std::optional<bytes> unknown;
  size_t decode(Envoy::Buffer::Instance& buffer, size_t limit) {
    auto index = std::distance(option_names.begin(),
                               std::find(option_names.begin(), option_names.end(), *key_field_));
    if (index == option_names.size()) {
      auto data = static_cast<uint8_t*>(buffer.linearize(limit));
      unknown = bytes{data, data + limit};
      buffer.drain(limit);
      return limit;
    } else if (unknown.has_value()) {
      unknown->clear();
    }
    return (*(decoders.begin() + index))(oneof, buffer, limit);
  }
  size_t encode(Envoy::Buffer::Instance& buffer) const {
    if (unknown.has_value()) {
      buffer.add(unknown->data(), unknown->size());
      return unknown->size();
    }
    auto index = oneof.index();
    if (index == 0) { // monostate
      return 0;
    }
    // subtract 1 because monostate is index 0
    return (*(encoders.begin() + index - 1))(oneof, buffer);
  }

  decltype(auto) visit(auto... fns) const {
    return std::visit(overloads{fns...}, oneof);
  }

  decltype(auto) visit(auto... fns) {
    return std::visit(overloads{fns...}, oneof);
  }

private:
  field<std::string, LengthPrefixed>* key_field_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

template <typename T, Envoy::Extensions::NetworkFilters::GenericProxy::Codec::FieldOptions Opt>
struct fmt::formatter<Envoy::Extensions::NetworkFilters::GenericProxy::Codec::field<T, Opt>> : fmt::formatter<T> {
  // parse is inherited from formatter<string_view>.

  auto format(Envoy::Extensions::NetworkFilters::GenericProxy::Codec::field<T, Opt> c, format_context& ctx) const
      -> format_context::iterator {
    return formatter<T>::format(c.value, ctx);
  }
};
