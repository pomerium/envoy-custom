#pragma once

#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include <type_traits>

namespace wire::test {

template <typename T>
struct test_field_reflect;

#define EXPAND_CALL_1(f1) visitor(m.f1);
#define EXPAND_CALL_2(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_1(__VA_ARGS__)
#define EXPAND_CALL_3(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_2(__VA_ARGS__)
#define EXPAND_CALL_4(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_3(__VA_ARGS__)
#define EXPAND_CALL_5(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_4(__VA_ARGS__)
#define EXPAND_CALL_6(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_5(__VA_ARGS__)
#define EXPAND_CALL_7(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_6(__VA_ARGS__)
#define EXPAND_CALL_8(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_7(__VA_ARGS__)
#define EXPAND_CALL_9(f1, ...) \
  visitor(m.f1);               \
  EXPAND_CALL_8(__VA_ARGS__)
#define EXPAND_CALL_10(f1, ...) \
  visitor(m.f1);                \
  EXPAND_CALL_9(__VA_ARGS__)
#define EXPAND_CALL_11(f1, ...) \
  visitor(m.f1);                \
  EXPAND_CALL_10(__VA_ARGS__)
#define EXPAND_CALL_12(f1, ...) \
  visitor(m.f1);                \
  EXPAND_CALL_11(__VA_ARGS__)
#define EXPAND_CALL_13(f1, ...) \
  visitor(m.f1);                \
  EXPAND_CALL_12(__VA_ARGS__)
#define EXPAND_CALL_14(f1, ...) \
  visitor(m.f1);                \
  EXPAND_CALL_13(__VA_ARGS__)
#define EXPAND_CALL_15(f1, ...) \
  visitor(m.f1);                \
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

#define TEST_FIELDS(msg, ...)                                                                    \
  template <>                                                                                    \
  struct test_field_reflect<msg> {                                                               \
    static constexpr void visit_fields([[maybe_unused]] msg& m, [[maybe_unused]] auto visitor) { \
      __VA_OPT__(EXPAND_CALLS(__VA_ARGS__))                                                      \
    };                                                                                           \
  };

template <typename T, EncodingOptions Opt>
struct test_field_reflect<wire::field<T, Opt>> {
  static constexpr void visit_fields(wire::field<T, Opt>& m, auto visitor) {
    visitor(m);
  }
};
template <>
struct test_field_reflect<wire::PubKeyUserAuthRequestMsg> {
  static constexpr void visit_fields(wire::PubKeyUserAuthRequestMsg& m, auto visitor) {
    visitor(m.public_key);
    visitor(m.public_key_alg);
    visitor(m.has_signature);
    visitor(m.signature);
  }
};

template <typename... Overloads>
struct test_field_reflect<wire::OverloadedMessage<Overloads...>> {
  static constexpr void visit_fields(wire::OverloadedMessage<Overloads...>& m, auto visitor) {
    auto random_index = absl::Uniform<size_t>(detail::rng, 0, sizeof...(Overloads));
    // choose one of the overloads at random
    auto resolvers = {std::function{[&]() {
      Overloads o;
      visitor(o);
      m.reset(std::move(o));
    }}...};
    (*std::next(std::begin(resolvers), random_index))();
  };
};

template <typename... Options>
struct test_field_reflect<wire::sub_message<Options...>> {
  static constexpr void visit_fields(wire::sub_message<Options...>& m, auto visitor) {
    auto random_index = absl::Uniform<size_t>(detail::rng, 0, sizeof...(Options));
    // choose one of the options at random
    auto resolvers = {std::function{[&]() {
      Options o;
      visitor(o);
      m.reset(std::move(o));
    }}...};
    (*std::next(std::begin(resolvers), random_index))();
  };
};

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
TEST_FIELDS(ChannelOpenMsg,
            channel_type,
            sender_channel,
            initial_window_size,
            max_packet_size,
            extra);
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
TEST_FIELDS(HostKeysProveRequestMsg,
            hostkeys);
TEST_FIELDS(HostKeysProveResponseMsg,
            signatures);
TEST_FIELDS(KeyboardInteractiveUserAuthRequestMsg,
            language_tag,
            submethods);
TEST_FIELDS(NoneAuthRequestMsg);
TEST_FIELDS(ServerSigAlgsExtension,
            public_key_algorithms_accepted);
TEST_FIELDS(PingExtension,
            version);
TEST_FIELDS(Extension,
            extension);
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
            echo)

template <typename T>
struct is_field : std::false_type {};

template <typename T, EncodingOptions Opt>
struct is_field<wire::field<T, Opt>> : std::true_type {};

static_assert(is_field<wire::field<uint32_t>>::value);
static_assert(is_field<wire::field<std::string, LengthPrefixed>>::value);
static_assert(!is_field<KexInitMsg>::value);

template <typename T>
void populateFields(T& msg) {
  test_field_reflect<T>::visit_fields(msg, []<typename Field>(this auto self, Field& field) -> void {
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