#pragma once

#include <algorithm>
#include <cstdint>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

#pragma clang unsafe_buffer_usage begin
#include "absl/strings/escaping.h"
#include "fmt/ranges.h"
#pragma clang unsafe_buffer_usage end

#include "source/common/visit.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/util.h"

namespace wire {

template <typename T, EncodingOptions Opt>
struct field_base {
  T value{};

  using value_type = T;
  static constexpr EncodingOptions encoding_options = Opt;

  field_base() = default;
  field_base(const field_base& other) = default;
  field_base(field_base&& other) noexcept = default;
  field_base& operator=(const field_base&) = default;
  field_base& operator=(field_base&&) noexcept = default;

  constexpr field_base(const T& t)
      : value(t) {}
  constexpr field_base(T&& t)
      : value(std::move(t)) {}

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t limit) noexcept {
    try {
      return read_opt<Opt>(buffer, value, limit);
    } catch (const Envoy::EnvoyException& e) {
      return absl::InvalidArgumentError(e.what());
    }
  }

  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    return write_opt<Opt>(buffer, value);
  }

  // implicit conversion operator: allow field<T> to be treated as T in some contexts
  operator T(this auto& self) { return self.value; }

  // arrow operator: allow using -> to access the value stored in a field
  auto* operator->(this auto& self) { return std::addressof(self.value); }

  // dereference operator: allow using * to access the value stored in a field
  auto& operator*(this auto& self) { return self.value; }

  // index operator: allow using [] to index into the vector of a field<vector<T>>
  auto& operator[](this auto& self, int i) { return self.value[i]; }

  // default comparison operators: comparing fields will compare their values
  auto operator<=>(const field_base& other) const = default;
  bool operator==(const field_base& other) const = default;

  // assignments to field<T> will assign T using its own assignment operators
  field_base& operator=(const T& rhs) {
    value = rhs;
    return *this;
  }

  // moves to field<T> will assign T using its own move assignment operators
  field_base& operator=(T&& rhs) {
    value = std::move(rhs);
    return *this;
  }

  // comparisons between field<T> and T will compare the values directly
  auto operator<=>(const T& other) const {
    return value <=> other;
  }

  // equality comparison between field<T> and T will compare the values directly
  bool operator==(const T& t) const {
    return value == t;
  }
};

template <typename T, EncodingOptions Opt = None>
  requires ReadWriter<type_or_value_type_t<T>>
struct field : field_base<T, Opt> {
  static_assert(sizeof(field_base<T, Opt>) == sizeof(T));
  using field_base<T, Opt>::field_base;
  using field_base<T, Opt>::value;
  using field_base<T, Opt>::operator=;
};

template <typename T>
struct is_field : std::false_type {};

template <typename T, EncodingOptions Opt>
struct is_field<field<T, Opt>> : std::true_type {};

template <typename T>
static constexpr bool is_field_v = is_field<T>::value;

// Utility function to decode a message, including a message type and a list of fields. The decoded
// message type is validated to ensure it matches the expected type. Returns the total number of
// bytes read (including the message type byte).
template <typename... Fields>
absl::StatusOr<size_t> decodeMsg(Envoy::Buffer::Instance& buffer, SshMessageType msg_type, explicit_size_t auto limit, Fields&&... fields) noexcept {
  if (limit == 0) {
    return 0;
  }
  if (buffer.length() < limit) {
    return absl::InvalidArgumentError("short read");
  }
  if (auto mt = buffer.drainInt<SshMessageType>(); mt != msg_type) {
    return absl::InvalidArgumentError(
      fmt::format("decoded unexpected message type {}, expected {}", mt, msg_type));
  }
  auto n = decodeSequence(buffer, limit - 1, std::forward<Fields>(fields)...);
  if (n.ok()) {
    return 1 + *n;
  }
  return n;
}

// Utility function to encode a message, including a message type and a list of fields. Returns
// the total number of bytes written (including the message type byte).
template <typename... Fields>
  requires (sizeof...(Fields) > 0)
absl::StatusOr<size_t> encodeMsg(Envoy::Buffer::Instance& buffer, SshMessageType msg_type, const Fields&... fields) noexcept {
  buffer.writeByte(msg_type);
  auto n = encodeSequence(buffer, fields...);
  if (n.ok()) {
    return 1 + *n;
  }
  return n;
}

template <typename T>
struct canonical_key_type : std::type_identity<T> {};

template <>
struct canonical_key_type<std::string_view> : std::type_identity<std::string> {};

template <typename T>
using canonical_key_type_t = canonical_key_type<T>::type;

template <typename... Options>
struct sub_message;

namespace detail {
template <typename... Options>
struct is_sub_message<sub_message<Options...>> : std::true_type {};

// Wrapper around sub_message::key_field to mangle the type of the sub_message into the type of
// the key. Only used for compile-time checks.
template <typename KeyField, typename SubMessage>
struct key_field_t : KeyField {
  using KeyField::KeyField;
  using KeyField::operator=;
};
} // namespace detail

// sub_message is used in place of a [field] for fields that contain one of several potential
// messages, where the type of the message is indicated by a "key field" in the same message.
// This is a very common pattern used in SSH messages; messages that are "containers" for other
// method-specific messages all have similar predictable behavior. sub_message is a type-safe
// container that performs several compile-time validations on the message types given, and allows
// accessing the stored message in a "type-switch" style manner using std::visit with lambdas.
template <typename... Options>
struct sub_message {
  // This validates that all options have the same message type. This helps avoid accidentally
  // adding messages for the wrong type into a sub-message list. (the "type" here is an opaque ID)
  static_assert(all_types_equal<typename Options::submsg_group...>,
                "all sub-message options must belong to the same group");
  static_assert(all_values_equal<Options::submsg_key_encoding...>,
                "all sub-message keys must have the same encoding");
  static_assert(all_types_equal<std::decay_t<decltype(Options::submsg_key)>...>,
                "all sub-message keys must have the same type");
  static_assert(all_values_unique({Options::submsg_key...}),
                "all sub-message keys must be unique");
  static_assert((std::is_copy_constructible_v<Options> && ...),
                "all options must be copy constructible");
  static_assert((std::is_move_constructible_v<Options> && ...),
                "all options must be move constructible");

  using key_type = first_type_t<canonical_key_type_t<std::decay_t<decltype(Options::submsg_key)>>...>;
  static constexpr EncodingOptions key_encoding = std::get<0>(std::tuple{Options::submsg_key_encoding...});
  using key_field_type = detail::key_field_t<field<key_type, key_encoding>, sub_message>;

  template <typename T>
  static consteval bool has_option() {
    return contains_type<T, Options...>;
  }

  constexpr sub_message() = default;

  template <typename T>
    requires (has_option<std::decay_t<T>>())
  constexpr sub_message(T&& t)
      : oneof(std::forward<T>(t)),
        key_field_(std::decay_t<T>::submsg_key) {}

  // oneof holds one of the messages in Options, or no value.
  std::optional<std::variant<Options...>> oneof;

  constexpr auto& key_field(this auto& self) { return self.key_field_; }

  // Assignment operator for any type in the options list. When a message is assigned, the
  // key field in the containing message is updated with the new message's key.
  template <typename T>
    requires (has_option<std::decay_t<T>>())
  sub_message& operator=(T&& other) {
    reset(std::forward<T>(other));
    return *this;
  }

  bool operator==(const sub_message& other) const = default;

  // Sets or updates the stored sub-message. This also updates the key field in the containing
  // message with the new message's key.
  template <typename T>
    requires (has_option<std::decay_t<T>>())
  void reset(T&& other) {
    // Forward 'other' into the variant using a copy if it is T&, or a move if it is T&&.
    oneof.emplace(std::forward<T>(other));
    // update the key field
    key_field_.value = std::decay_t<T>::submsg_key;
  }

  // Wrappers around std::get to obtain the value in the variant for a specific type.
  // The oneof must currently have a value.
  template <typename T>
  constexpr decltype(auto) get(this auto& self) { return std::get<T>(*self.oneof); }
  template <size_t I>
  constexpr decltype(auto) get(this auto& self) { return std::get<I>(*self.oneof); }

  template <typename T>
  constexpr bool holds_alternative() const {
    return oneof.has_value() && std::holds_alternative<T>(*oneof);
  }

  // Reads from the buffer and decodes the contained message. The type is determined by the
  // current value of the key field. It is expected that the key field has already been decoded.
  //
  // If the key field does not correspond to one of the known message types for this sub-message,
  // the raw bytes of the message will be read and stored in the 'unknown' field, and the oneof
  // variant will be reset. Likewise, the 'unknown' field will be cleared if a known message is
  // decoded.
  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t limit) noexcept {
    // Find the index of the current key in option_keys. The key is read from the previously set
    // key field. If there is no set key, it is treated as an unknown message.
    auto it = option_index_lookup.find(*key_field_);
    if (it != option_index_lookup.end()) [[likely]] {
      unknown_.reset(); // reset unknown bytes if present (see note in decodeUnknown)
      return decoders[it->second](oneof, buffer, limit);
    }

    // not found
    unknown_ = flushTo<bytes>(buffer, limit);
    oneof.reset();
    return limit;
  }

  // Encodes the currently stored message and writes it to the buffer. If no message is stored,
  // does nothing. If an unknown message is stored, it will write the raw bytes of that message
  // to the buffer. Returns the total number of bytes written.
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    if (oneof.has_value()) [[likely]] {
      return encoders[(*oneof).index()](*oneof, buffer);
    }
    if (unknown_) {
      buffer.add(unknown_->data(), unknown_->size());
      return unknown_->size();
    }
    return 0;
  }

  // Decodes the message contained in the unknown bytes field.
  absl::StatusOr<size_t> decodeUnknown() noexcept {
    if (!unknown_.has_value()) [[unlikely]] {
      ENVOY_BUG(false, "decodeUnknown() called with known value");
      return absl::InternalError("decodeUnknown() called with known value");
    }
    bytes unknown_bytes = *std::exchange(unknown_, std::optional<bytes>{});
    return with_buffer_view(unknown_bytes, [this](Envoy::Buffer::Instance& buffer) {
      return this->decode(buffer, buffer.length());
    });
  }

  // Wrapper around std::visit. To use this function, pass one or more lambda functions of the form
  //  [](const T& msg) { ... }
  // where T is one of the option types. The matching lambda will be called for the value stored
  // in oneof. This functions similarly to a "type-switch" operation.
  // A "default" case can be provided by passing a lambda of the form
  //  [](auto msg) { ... }
  // and will be invoked if none of the other lambdas match.
  template <typename Self>
  [[nodiscard]] constexpr decltype(auto) visit(this Self&& self, auto... fns) {
    if (self.oneof.has_value()) [[likely]] {
      return std::visit(make_overloads<basic_visitor, Self&&>(fns...), *std::forward<Self>(self).oneof);
    }
    using return_type = decltype(std::visit(make_overloads<basic_visitor, Self&&>(fns...), *std::forward<Self>(self).oneof));
    if constexpr (!std::is_void_v<return_type>) {
      return return_type{};
    }
  }

  std::optional<bytes> getUnknownBytesForTest() const { return unknown_; }

private:
  // unknown holds raw bytes for an unknown message type.
  std::optional<bytes> unknown_;

  key_field_type key_field_;

  // Contains a list of sub-message keys for each option type in the order provided.
  // All option types must be unique.
  static constexpr std::array option_keys = {Options::submsg_key...};

  // Lookup table for finding the index in option_keys for each known key. Keys can have e.g.
  // string types, so we can't assume they can always be repurposed as indexes.
  // The result is a map of key:index, like
  //  {<key1>: 0, <key2>: 1, <key3>: 2}
  static inline const auto option_index_lookup = []<size_t... I>(std::index_sequence<I...>) {
    return absl::flat_hash_map<key_type, size_t>{{std::pair{key_type{option_keys[I]}, I}...}};
  }(std::index_sequence_for<Options...>{});

  using oneof_type = decltype(oneof)::value_type;
  // Decoders is a list of functions, one for each type in Options, where each function decodes
  // that type and assigns it to the oneof. The order is the same as in option_keys, so the
  // matching decoder can be looked up by index of the key and called to decode the corresponding
  // type. The result is a list of functions, like
  //  [<decoder for A>, <decoder for B>, <decoder for C>] (where Options == <A, B, C>)
  static constexpr std::array decoders =
    {+[](std::optional<oneof_type>& oneof, Envoy::Buffer::Instance& buffer, size_t limit) noexcept -> absl::StatusOr<size_t> {
      Options opt; // 'Options' is a placeholder, substituted for one of the contained types
      auto n = opt.decode(buffer, limit);
      if (n.ok()) {
        oneof.emplace(std::move(opt));
      }
      return n;
    }...}; // the expression preceding '...' is repeated for each type in Options.

  // Encoders is a list constructed the same way as decoders, but for writing the messages instead.
  // The encoder for each type is retrieved using std::get<T>(variant), which returns the value
  // for that type (and asserts that it is the actual type stored in the variant).
  static constexpr std::array encoders =
    {+[](const oneof_type& oneof, Envoy::Buffer::Instance& buffer) noexcept -> absl::StatusOr<size_t> {
      return std::get<Options>(oneof).encode(buffer);
    }...};
};
} // namespace wire

// fmt::formatter specialization for field types - formats the value contained in the field.
template <typename T, wire::EncodingOptions Opt>
  requires (!is_vector_v<T> || is_bytes_v<T>)
struct fmt::formatter<wire::field<T, Opt>> : fmt::formatter<T> {
  auto format(const wire::field<T, Opt>& f, format_context& ctx) const
    -> format_context::iterator {
    return formatter<T>::format(f.value, ctx);
  }
};

template <typename T, wire::EncodingOptions Opt>
  requires (!std::is_same_v<T, uint8_t>)
struct fmt::formatter<wire::field<std::vector<T>, Opt>> : formatter<string_view> {
  auto format(const wire::field<std::vector<T>, Opt>& f, format_context& ctx) const
    -> format_context::iterator {
    return formatter<string_view>::format(fmt::format("{}", f.value), ctx);
  }
};

template <>
struct fmt::formatter<bytes> : fmt::formatter<string_view> {
  auto format(const ::bytes& b, format_context& ctx) const
    -> format_context::iterator {
    return fmt::formatter<string_view>::format(
      absl::BytesToHexString(std::string_view{reinterpret_cast<const char*>(b.data()), b.size()}), ctx);
  }
};
