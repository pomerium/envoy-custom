#pragma once

#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include <type_traits>

namespace wire {
template <typename T>
struct test_field_reflect;
}

template <typename T>
concept FieldReflectable = requires(T t) {
  wire::test_field_reflect<T>::visit_fields(t, [](std::string_view, auto&&) {});
};

#define EXPAND_CALL_1(f1) visitor(#f1, m.f1);
#define EXPAND_CALL_2(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_1(__VA_ARGS__)
#define EXPAND_CALL_3(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_2(__VA_ARGS__)
#define EXPAND_CALL_4(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_3(__VA_ARGS__)
#define EXPAND_CALL_5(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_4(__VA_ARGS__)
#define EXPAND_CALL_6(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_5(__VA_ARGS__)
#define EXPAND_CALL_7(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_6(__VA_ARGS__)
#define EXPAND_CALL_8(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_7(__VA_ARGS__)
#define EXPAND_CALL_9(f1, ...) \
  visitor(#f1, m.f1);          \
  EXPAND_CALL_8(__VA_ARGS__)
#define EXPAND_CALL_10(f1, ...) \
  visitor(#f1, m.f1);           \
  EXPAND_CALL_9(__VA_ARGS__)
#define EXPAND_CALL_11(f1, ...) \
  visitor(#f1, m.f1);           \
  EXPAND_CALL_10(__VA_ARGS__)
#define EXPAND_CALL_12(f1, ...) \
  visitor(#f1, m.f1);           \
  EXPAND_CALL_11(__VA_ARGS__)
#define EXPAND_CALL_13(f1, ...) \
  visitor(#f1, m.f1);           \
  EXPAND_CALL_12(__VA_ARGS__)
#define EXPAND_CALL_14(f1, ...) \
  visitor(#f1, m.f1);           \
  EXPAND_CALL_13(__VA_ARGS__)
#define EXPAND_CALL_15(f1, ...) \
  visitor(#f1, m.f1);           \
  EXPAND_CALL_14(__VA_ARGS__)

#define GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, \
                  _11, _12, _13, _14, _15, NAME, ...) NAME

#define EXPAND_CALLS(...)                                   \
  GET_MACRO(__VA_ARGS__,                                    \
            EXPAND_CALL_15, EXPAND_CALL_14, EXPAND_CALL_13, \
            EXPAND_CALL_12, EXPAND_CALL_11, EXPAND_CALL_10, \
            EXPAND_CALL_9, EXPAND_CALL_8, EXPAND_CALL_7,    \
            EXPAND_CALL_6, EXPAND_CALL_5, EXPAND_CALL_4,    \
            EXPAND_CALL_3, EXPAND_CALL_2, EXPAND_CALL_1)    \
  (__VA_ARGS__)

#define FORMAT_FIELDS(msg, ...)                                                                      \
  template <>                                                                                        \
  struct fmt::formatter<wire::msg> : formatter<string_view> {                                        \
    auto format(const ::wire::msg& m, format_context& ctx) const -> format_context::iterator {       \
      auto out = fmt::memory_buffer();                                                               \
      out.append(std::string_view(#msg ":\n"));                                                      \
      ::wire::test_field_reflect<::wire::msg>::visit_fields(m, [&](std::string_view name, auto& f) { \
        out.append(std::string_view("  "));                                                          \
        out.append(name);                                                                            \
        out.append(std::string_view(": "));                                                          \
        fmt::format_to(std::back_inserter(out), "{}", f);                                            \
        out.append(std::string_view("\n"));                                                          \
      });                                                                                            \
      return formatter<string_view>::format(fmt::to_string(out), ctx);                               \
    }                                                                                                \
  };                                                                                                 \
  static_assert(FieldReflectable<wire::msg>);

#define TEST_FIELDS(msg, ...)                                                                  \
  template <>                                                                                  \
  struct wire::test_field_reflect<wire::msg> {                                                 \
    template <typename T>                                                                      \
      requires std::same_as<std::decay_t<T>, wire::msg>                                        \
    static constexpr void visit_fields([[maybe_unused]] T& m, [[maybe_unused]] auto visitor) { \
      __VA_OPT__(EXPAND_CALLS(__VA_ARGS__))                                                    \
    };                                                                                         \
  };                                                                                           \
  FORMAT_FIELDS(msg, __VA_ARGS__)

template <typename... Overloads>
struct wire::test_field_reflect<wire::OverloadSet<Overloads...>> {
  static constexpr void visit_fields(OverloadSet<Overloads...>& m, auto visitor) {
    auto random_index = absl::Uniform<size_t>(test::detail::rng, 0, sizeof...(Overloads));
    // choose one of the overloads at random
    using visitor_type = decltype(visitor);
    auto resolvers = {+[](OverloadSet<Overloads...>& m, visitor_type visitor) {
      Overloads o;
      visitor("", o);
      m.reset(std::move(o));
    }...};
    (*std::next(std::begin(resolvers), random_index))(m, visitor);
  };
};

template <typename... Options>
struct wire::test_field_reflect<wire::sub_message<Options...>> {
  static constexpr void visit_fields(sub_message<Options...>& m, auto visitor) {
    auto random_index = absl::Uniform<size_t>(test::detail::rng, 0, sizeof...(Options));
    // choose one of the options at random
    using visitor_type = decltype(visitor);
    auto resolvers = {+[](sub_message<Options...>& m, visitor_type visitor) {
      Options o;
      visitor("", o);
      m.reset(std::move(o));
    }...};
    (*std::next(std::begin(resolvers), random_index))(m, visitor);
  };
};

template <typename... Options>
struct fmt::formatter<wire::sub_message<Options...>> : formatter<string_view> {
  auto format(const ::wire::sub_message<Options...> msg, format_context& ctx) const
    -> format_context::iterator {
    if (!msg.oneof.has_value()) {
      return formatter<string_view>::format("sub_message holding no value", ctx);
    }
    return formatter<string_view>::format(
      msg.visit([&](const Options& v) {
        return fmt::format("sub_message holding {}", v);
      }...),
      ctx);
  }
};

namespace wire {
template <typename... Options>
std::ostream& operator<<(std::ostream& os, const wire::sub_message<Options...>& msg) {
  return os << fmt::to_string(msg);
}
} // namespace wire

template <typename... Args>
struct fmt::formatter<wire::OverloadSet<Args...>> : formatter<string_view> {
  auto format(const wire::OverloadSet<Args...>&, format_context& ctx) const
    -> format_context::iterator {
    return formatter<string_view>::format(
      fmt::format("[overloaded message: {}]", std::vector<string_view>{type_name<Args>()...}), ctx);
  }
};

namespace wire {
template <typename... Args>
std::ostream& operator<<(std::ostream& os, const OverloadSet<Args...>& msg) {
  return os << fmt::to_string(msg);
}
} // namespace wire

template <>
struct fmt::formatter<wire::Message> : formatter<decltype(wire::Message::message)> {
  auto format(const wire::Message& f, format_context& ctx) const
    -> format_context::iterator {
    return formatter<decltype(f.message)>::format(f.message, ctx);
  }
};

namespace wire {
inline std::ostream& operator<<(std::ostream& os, const Message& msg) {
  return os << fmt::to_string(msg);
}
} // namespace wire

TEST_FIELDS(DisconnectMsg,
            reason_code,
            description,
            language_tag);
TEST_FIELDS(IgnoreMsg,
            data);
TEST_FIELDS(UnimplementedMsg,
            sequence_number);
TEST_FIELDS(DebugMsg,
            always_display,
            message,
            language_tag);
TEST_FIELDS(ServiceRequestMsg,
            service_name);
TEST_FIELDS(ServiceAcceptMsg,
            service_name);
TEST_FIELDS(ServerSigAlgsExtension,
            public_key_algorithms_accepted);
TEST_FIELDS(PingExtension,
            version);
TEST_FIELDS(ExtInfoInAuthExtension,
            version);
TEST_FIELDS(Extension,
            extension);
TEST_FIELDS(ExtInfoMsg,
            extensions);
TEST_FIELDS(KexInitMsg,
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            reserved);
TEST_FIELDS(NewKeysMsg);
TEST_FIELDS(UserAuthRequestMsg,
            username,
            service_name,
            request);
TEST_FIELDS(UserAuthFailureMsg,
            methods,
            partial);
TEST_FIELDS(UserAuthSuccessMsg);
TEST_FIELDS(UserAuthBannerMsg,
            message,
            language_tag);
TEST_FIELDS(GlobalRequestMsg,
            want_reply,
            request);
TEST_FIELDS(GlobalRequestSuccessMsg,
            response);
TEST_FIELDS(GlobalRequestFailureMsg);
TEST_FIELDS(SessionChannelOpenMsg);
TEST_FIELDS(X11ChannelOpenMsg,
            originator_address,
            originator_port);
TEST_FIELDS(ForwardedTcpipChannelOpenMsg,
            address_connected,
            port_connected,
            originator_address,
            originator_port);
TEST_FIELDS(DirectTcpipChannelOpenMsg,
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port);
TEST_FIELDS(ChannelOpenMsg,
            sender_channel,
            initial_window_size,
            max_packet_size,
            request);
TEST_FIELDS(ChannelOpenConfirmationMsg,
            recipient_channel,
            sender_channel,
            initial_window_size,
            max_packet_size,
            extra);
TEST_FIELDS(ChannelOpenFailureMsg,
            recipient_channel,
            reason_code,
            description,
            language_tag);
TEST_FIELDS(ChannelWindowAdjustMsg,
            recipient_channel,
            bytes_to_add);
TEST_FIELDS(ChannelDataMsg,
            recipient_channel,
            data);
TEST_FIELDS(ChannelExtendedDataMsg,
            recipient_channel,
            data_type_code,
            data);
TEST_FIELDS(ChannelEOFMsg,
            recipient_channel);
TEST_FIELDS(ChannelCloseMsg,
            recipient_channel);
TEST_FIELDS(ChannelRequestMsg,
            recipient_channel,
            want_reply,
            request);
TEST_FIELDS(ChannelSuccessMsg,
            recipient_channel);
TEST_FIELDS(ChannelFailureMsg,
            recipient_channel);
TEST_FIELDS(PingMsg,
            data);
TEST_FIELDS(PongMsg,
            data);

// overloaded message types
TEST_FIELDS(KexEcdhInitMsg,
            client_pub_key);
TEST_FIELDS(KexEcdhReplyMsg,
            host_key,
            ephemeral_pub_key,
            signature);
TEST_FIELDS(UserAuthPubKeyOkMsg,
            public_key_alg,
            public_key);
TEST_FIELDS(UserAuthInfoRequestMsg,
            name,
            instruction,
            language_tag,
            prompts);
TEST_FIELDS(UserAuthInfoResponseMsg,
            responses);

// sub-messages

// This message is special: its decode method does not read the signature field at all if
// has_signature=false. Encoding a message with has_signature=false and a non-empty signature,
// then decoding it, will not result in the same message. Therefore we will only generate valid
// messages, i.e. where has_signature is "correct".
template <>
struct wire::test_field_reflect<wire::PubKeyUserAuthRequestMsg> {
  template <typename T>
    requires std::same_as<std::decay_t<T>, wire::PubKeyUserAuthRequestMsg>
  static constexpr void visit_fields(T& m, auto visitor) {
    visitor("has_signature", m.has_signature);
    visitor("public_key_alg", m.public_key_alg);
    visitor("public_key", m.public_key);
    if (m.has_signature) {
      visitor("signature", m.signature);
    }
  };
};
FORMAT_FIELDS(PubKeyUserAuthRequestMsg,
              has_signature,
              public_key_alg,
              public_key,
              signature);
TEST_FIELDS(HostKeysProveRequestMsg,
            hostkeys);
TEST_FIELDS(HostKeysProveResponseMsg,
            signatures);
TEST_FIELDS(TcpipForwardResponseMsg,
            server_port);
TEST_FIELDS(KeyboardInteractiveUserAuthRequestMsg,
            language_tag,
            submethods);
TEST_FIELDS(NoneAuthRequestMsg);

TEST_FIELDS(PtyReqChannelRequestMsg,
            term_env,
            width_columns,
            height_rows,
            width_px,
            height_px,
            modes);
TEST_FIELDS(WindowDimensionChangeChannelRequestMsg,
            width_columns,
            height_rows,
            width_px,
            height_px);
TEST_FIELDS(ShellChannelRequestMsg);
TEST_FIELDS(HostKeysMsg,
            hostkeys);
TEST_FIELDS(UserAuthInfoPrompt,
            prompt,
            echo);
TEST_FIELDS(TcpipForwardMsg,
            remote_address,
            remote_port);
TEST_FIELDS(CancelTcpipForwardMsg,
            remote_address,
            remote_port);

namespace wire {

template <typename T>
  requires wire::is_field_v<T> || FieldReflectable<T>
std::ostream& operator<<(std::ostream& os, const T& t) {
  return os << fmt::to_string(t);
}

} // namespace wire

namespace wire::test {

template <typename T>
void populateFields(T& msg) {
  test_field_reflect<T>::visit_fields(msg, []<typename Field>(this auto self, std::string_view, Field& field) -> void {
    using field_type = std::decay_t<Field>;
    if constexpr (is_field<field_type>::value) {
      field = random_value<typename field_type::value_type>();
      if constexpr ((field_type::encoding_options & CommaDelimited) != 0) {
        // remove empty elements
        field.value.erase(std::remove_if(field.value.begin(), field.value.end(),
                                         [](const auto& elem) { return elem.empty(); }),
                          field.value.end());
      }
    } else {
      test_field_reflect<field_type>::visit_fields(field, self);
    }
  });
}

template <>
struct detail::random_value_impl<wire::Extension> {
  static constexpr auto operator()() {
    wire::Extension ext;
    populateFields(ext);
    return ext;
  }
};

template <>
struct detail::random_value_impl<UserAuthInfoPrompt> {
  static constexpr auto operator()() {
    UserAuthInfoPrompt ext;
    populateFields(ext);
    return ext;
  }
};

} // namespace wire::test