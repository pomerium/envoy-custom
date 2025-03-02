#pragma once

#include "common.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "util.h"
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace wire {

template <typename T, EncodingOptions Opt>
struct field_base {
  T value{};
  field_base() = default;
  field_base(const field_base& other)
      : value(other) {};
  field_base(field_base&& other) noexcept
      : value(std::move(other.value)) {}

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
  operator T() const& { return value; }
  operator T() & { return value; }

  // arrow operator: allow using -> to access the value stored in a field
  T* operator->() { return &value; }
  const T* operator->() const { return &value; }

  // dereference operator: allow using * to access the value stored in a field
  T& operator*() { return value; }
  const T& operator*() const { return value; }

  // index operator: allow using [] to index into the vector of a field<vector<T>>
  auto operator[](int i) const { return value[i]; }
  auto operator[](int i) { return value[i]; }

  // default comparison operators: comparing fields will compare their values
  auto operator<=>(const field_base& other) const = default;
  bool operator==(const field_base& other) const = default;

  // assignments to field<T> will assign T using its own assignment operators
  field_base& operator=(const T& rhs) {
    value = rhs;
    return *this;
  }
  field_base& operator=(const field_base& rhs) = default;

  // same as above, but initializer_list needs its own specialization
  field_base& operator=(std::initializer_list<T> rhs) {
    value = rhs;
    return *this;
  }

  // moves to field<T> will assign T using its own move assignment operators
  field_base& operator=(T&& rhs) {
    value = std::move(rhs);
    return *this;
  }

  // moves to field<T> will assign T using its own move assignment operators
  field_base& operator=(field_base&& rhs) noexcept {
    value = std::move(rhs.value);
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

template <typename T, EncodingOptions Opt = None, typename = void>
  requires ReadWriter<type_or_value_type_t<T>>
struct field;

// normal field (not conditional)
template <typename T, EncodingOptions Opt>
  requires ReadWriter<type_or_value_type_t<T>>
struct field<T, Opt, std::enable_if_t<(Opt & Conditional) == 0>> : field_base<T, Opt> {
  static_assert(sizeof(field_base<T, Opt>) == sizeof(T));
  using field_base<T, Opt>::value;
  using field_base<T, Opt>::operator=;
};

// conditional field
template <typename T, EncodingOptions Opt>
  requires ReadWriter<type_or_value_type_t<T>>
struct field<T, Opt, std::enable_if_t<(Opt & Conditional) != 0>> : field_base<T, Opt> {
  static_assert(sizeof(field_base<T, Opt>) == sizeof(T));
  using field_base<T, Opt>::value;
  using field_base<T, Opt>::operator=;

  auto enableIf(bool condition) const {
    return conditional_encoder{
      .enabled = condition,
      .vp = const_cast<T*>(&value),
    };
  }

private:
  struct conditional_encoder {
    bool enabled;
    T* vp;
    absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t n) noexcept {
      if (!enabled) {
        return 0;
      }
      try {
        return read_opt<(Opt & ~Conditional)>(buffer, *vp, n);
      } catch (const Envoy::EnvoyException& e) {
        return absl::InvalidArgumentError(e.what());
      }
    }
    absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
      if (!enabled) {
        return 0;
      }

      return write_opt<(Opt & ~Conditional)>(buffer, *vp);
    }
  };
};

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
      fmt::format("decoded unexpected message type {}, expected {}",
                  static_cast<uint8_t>(mt),
                  static_cast<uint8_t>(msg_type)));
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
absl::StatusOr<size_t> encodeMsg(Envoy::Buffer::Instance& buffer, SshMessageType msg_type, const Fields&... fields) noexcept {
  buffer.writeByte(msg_type);
  auto n = encodeSequence(buffer, fields...);
  if (n.ok()) {
    return 1 + *n;
  }
  return n;
}

// used in std::visit to hold a list of lambda functions
// from https://en.cppreference.com/w/cpp/utility/variant/visit
template <typename... Ts>
struct overloads : Ts... {
  using Ts::operator()...;
};

// A sentinel type that can be used to construct a sub_message without a key field initially.
// Any message decoded by such a sub_message instance will be treated as unknown and stored as
// raw bytes. A key field can later be set using the set_key_field() method, then decode() can
// be called again to decode the typed message.
//
// This is used to handle a couple of unusual SSH messages that contain a sub message but no
// key field that can be used to determine its type without surrounding context.
struct defer_decoding_t {};
static constexpr const auto defer_decoding = defer_decoding_t{};

template <typename T>
struct canonical_key_type : std::type_identity<T> {};

template <>
struct canonical_key_type<std::string_view> : std::type_identity<std::string> {};

template <typename T>
using canonical_key_type_t = canonical_key_type<T>::type;

template <typename... Options>
struct sub_message;

// sub_message is used in place of a [field] for fields that contain one of several potential
// messages, where the type of the message is indicated by a (string) name in a previous field.
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

  using key_type = first_type_t<canonical_key_type_t<std::decay_t<decltype(Options::submsg_key)>>...>;
  static constexpr EncodingOptions key_encoding = std::get<0>(std::tuple{Options::submsg_key_encoding...});

  template <typename T>
  static constexpr bool has_option() {
    return contains_type<T, Options...>;
    // return (std::is_same_v<std::decay_t<T>, Options> || ...);
  }

  // oneof holds one of the messages in Options, or the empty (std::monostate) value.
  std::variant<std::monostate, Options...> oneof;

  sub_message(const sub_message&) = delete;
  sub_message(sub_message&&) = default;
  sub_message& operator=(const sub_message&) = delete;
  sub_message& operator=(sub_message&&) = default;

  explicit sub_message(field<key_type, key_encoding>& key_field)
      : key_field_(key_field) {};

  explicit sub_message(defer_decoding_t) {};

  // set_key_field updates the key field used to decode the message.
  void setKeyField(field<key_type, key_encoding>& key_field) {
    key_field_.emplace(key_field);
  }

  // Assignment operator for any type in the options list. When a message is assigned, the
  // key field in the containing message is updated with the new message's key.
  template <typename T>
  std::enable_if_t<has_option<T>(), sub_message&>
  operator=(T&& other) {
    // Forward 'other' into the variant using a copy if it is T&, or a move if it is T&&.
    oneof.template emplace<std::decay_t<T>>(std::forward<T>(other));
    // update the key field
    key_field_->value = std::decay_t<T>::submsg_key;
    return *this;
  }

  // wrappers around std::get to obtain the value in the variant for a specific type.
  template <typename T>
  decltype(auto) get() { return std::get<T>(oneof); }
  template <typename T>
  decltype(auto) get() const { return std::get<T>(oneof); }

  template <size_t I>
  decltype(auto) get() { return std::get<I + 1>(oneof); }
  template <size_t I>
  decltype(auto) get() const { return std::get<I + 1>(oneof); }

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
    auto it = option_index_lookup.end();
    if (key_field_.has_value()) {
      it = option_index_lookup.find(**key_field_);
    } else if (unknown_) {
      PANIC("bug: missing call to setKeyField");
    }
    if (it == option_index_lookup.end()) { // not found
      auto data = static_cast<uint8_t*>(buffer.linearize(limit));
      unknown_ = std::make_shared<bytes>(data, data + limit);
      buffer.drain(limit);
      oneof = std::monostate{}; // reset the oneof
      return limit;
    } else if (unknown_) {
      unknown_ = nullptr;
    }
    // this is just "decoders[index](...)" but initializer lists have no [] operator for some reason
    return (*(decoders.begin() + it->second))(oneof, buffer, limit);
  }

  // Encodes the currently stored message and writes it to the buffer. If no message is stored,
  // does nothing. If an unknown message is stored, it will write the raw bytes of that message
  // to the buffer. Returns the total number of bytes written.
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept {
    if (unknown_) {
      buffer.add(unknown_->data(), unknown_->size());
      return unknown_->size();
    }
    auto index = oneof.index();
    if (index == 0) { // monostate
      return 0;
    }
    // subtract 1 from the index because monostate is index 0, so the index of our option types
    // in the variant effectively starts at 1.
    return (*(encoders.begin() + index - 1))(oneof, buffer);
  }

  // Decodes the message contained in the unknown bytes field.
  absl::StatusOr<size_t> decodeUnknown() noexcept {
    if (!unknown_) {
      PANIC("bug: decodeUnknown() called with known value");
    }
    // hold a reference to the unknown bytes so they are not freed when decode() unsets it
    std::shared_ptr<bytes> unknown_ptr = unknown_;
    return with_buffer_view(*unknown_ptr, [this](Envoy::Buffer::Instance& buffer) {
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
  decltype(auto) visit(auto... fns) const {
    return std::visit(overloads{fns...}, oneof);
  }

  // Wrapper around std::visit for a mutable sub_message. This operates the same as the const
  // variation of this function, except the parameters to passed lambda functions must not be
  // const-qualified. That is, they must have the form:
  //  [](T& msg) { ... }
  decltype(auto) visit(auto... fns) {
    return std::visit(overloads{fns...}, oneof);
  }

private:
  // unknown holds raw bytes for an unknown message type.
  std::shared_ptr<bytes> unknown_;

  Envoy::OptRef<field<key_type, key_encoding>> key_field_;

  // Contains a list of sub-message keys for each option type in the order provided.
  // All option types must be unique.
  static constexpr std::array option_keys = {Options::submsg_key...};
  static inline const auto option_index_lookup = []<size_t... I>(std::index_sequence<I...>) {
    return std::unordered_map<key_type, size_t>{{std::pair{key_type{option_keys[I]}, I}...}};
  }(std::make_index_sequence<sizeof...(Options)>{});

  using oneof_type = decltype(oneof);
  // This strange looking syntax creates a list of functions, one for each type in Options, where
  // each function decodes that type and assigns it to the oneof. The order is the same as in
  // option_keys, so the matching decoder can be looked up by index of the key and called to decode
  // the corresponding type. The result is a list of functions, like
  //  {<decoder for A>, <decoder for B>, <decoder for C>} (where Options == <A, B, C>)
  static constexpr std::array decoders =
    {+[](oneof_type& oneof, Envoy::Buffer::Instance& buffer, size_t limit) noexcept -> absl::StatusOr<size_t> {
      Options opt; // 'Options' is a placeholder, substituted for one of the contained types
      auto n = opt.decode(buffer, limit);
      if (n.ok()) {
        oneof.template emplace<Options>(std::move(opt));
      }
      return n;
    }...}; // the expression preceding '...' is repeated for each type in Options.

  // Encoders is a list constructed the same way as decoders, but for writing the messages instead.
  // The encoder for each type is retrieved using std::get<T>(variant), which returns the value
  // for that type (and asserts that it is the actual type stored in the variant).
  static constexpr auto encoders =
    {+[](const oneof_type& oneof, Envoy::Buffer::Instance& buffer) noexcept -> absl::StatusOr<size_t> {
      return std::get<Options>(oneof).encode(buffer);
    }...};
};
} // namespace wire

// fmt::formatter specialization for field types - formats the value contained in the field.
template <typename T, wire::EncodingOptions Opt>
struct fmt::formatter<wire::field<T, Opt>> : fmt::formatter<T> {
  auto format(wire::field<T, Opt> c, format_context& ctx) const
    -> format_context::iterator {
    return formatter<T>::format(c.value, ctx);
  }
};
