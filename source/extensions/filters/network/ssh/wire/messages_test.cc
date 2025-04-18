#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/message_traits.h"
#include "source/extensions/filters/network/ssh/wire/wire_test_common.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/wire_test_util.h"

namespace wire::test {

TEST(MessagesTest, Message_Visit) {
  Message msg;

  auto non_overload = [&](const DisconnectMsg& _) {
    return SshMessageType::Disconnect;
  };
  auto overload = [&](opt_ref<const KexEcdhInitMessage> _) {
    return SshMessageType::KexInit;
  };
  auto defaultCase = [&](auto&) {
    return SshMessageType::KexInit;
  };

  EXPECT_STATIC_ASSERT(std::is_same_v<visitor_info_t<decltype(overload)>::arg_type_with_cv_optref,
                                      opt_ref<const KexEcdhInitMessage>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<visitor_info_t<decltype(overload)>::arg_type,
                                      KexEcdhInitMessage>);
  EXPECT_STATIC_ASSERT(wire::detail::is_top_level_message_v<KexEcdhInitMessage>);
  EXPECT_STATIC_ASSERT(wire::detail::is_top_level_message_v<DisconnectMsg>);

  EXPECT_STATIC_ASSERT(std::is_same_v<visitor_arg_type_t<decltype(overload)>,
                                      KexEcdhInitMessage>);
  EXPECT_STATIC_ASSERT(wire::detail::is_overload<visitor_arg_type_t<decltype(overload)>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<wire::detail::overload_for_t<visitor_arg_type_t<decltype(overload)>>,
                                      OverloadedMessage<KexEcdhInitMessage>>);
  EXPECT_STATIC_ASSERT(!wire::detail::top_level_visitor<false, decltype(overload)>::is_catchall_visitor);

  EXPECT_STATIC_ASSERT(std::is_same_v<visitor_arg_type_t<decltype(non_overload)>,
                                      DisconnectMsg>);
  EXPECT_STATIC_ASSERT(!wire::detail::is_overload<visitor_arg_type_t<decltype(non_overload)>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<wire::detail::overload_for_t<visitor_arg_type_t<decltype(non_overload)>>,
                                      DisconnectMsg>);
  EXPECT_STATIC_ASSERT(!wire::detail::top_level_visitor<false, decltype(non_overload)>::is_catchall_visitor);

  EXPECT_STATIC_ASSERT(wire::detail::top_level_visitor<false, decltype(defaultCase)>::is_catchall_visitor);
  EXPECT_STATIC_ASSERT(std::is_invocable_v<decltype([](any_of<wire::IgnoreMsg, wire::DebugMsg, wire::UnimplementedMsg> auto&) {}), wire::IgnoreMsg&>);
  EXPECT_STATIC_ASSERT(std::is_invocable_v<decltype([](wire::detail::TopLevelMessage auto&) {}), wire::IgnoreMsg&>);

  auto visitor = [&]() {
    return msg.visit(
      [&](const DisconnectMsg& _) {
        return SshMessageType::Disconnect;
      },
      [&](const IgnoreMsg& _) {
        return SshMessageType::Ignore;
      },
      [&](const UnimplementedMsg& _) {
        return SshMessageType::Unimplemented;
      },
      [&](const DebugMsg& _) {
        return SshMessageType::Debug;
      },
      [&](const ServiceRequestMsg& _) {
        return SshMessageType::ServiceRequest;
      },
      [&](const ServiceAcceptMsg& _) {
        return SshMessageType::ServiceAccept;
      },
      [&](const KexInitMessage& _) {
        return SshMessageType::KexInit;
      },
      [&](opt_ref<const KexEcdhInitMessage> _) {
        return SshMessageType::KexECDHInit;
      },
      [&](opt_ref<const UserAuthPubKeyOkMsg> _) {
        return SshMessageType::UserAuthPubKeyOk;
      },
      [&](const auto&) {
        return SshMessageType(-1);
      });
  };

  DisconnectMsg disconnect_msg;
  msg = disconnect_msg;
  EXPECT_EQ(SshMessageType::Disconnect, visitor());

  IgnoreMsg ignore_msg;
  msg = ignore_msg;
  EXPECT_EQ(SshMessageType::Ignore, visitor());

  UnimplementedMsg unimplemented_msg;
  msg = unimplemented_msg;
  EXPECT_EQ(SshMessageType::Unimplemented, visitor());

  DebugMsg debug_msg;
  msg = debug_msg;
  EXPECT_EQ(SshMessageType::Debug, visitor());

  ServiceRequestMsg service_request_msg;
  msg = service_request_msg;
  EXPECT_EQ(SshMessageType::ServiceRequest, visitor());

  ServiceAcceptMsg service_accept_msg;
  msg = service_accept_msg;
  EXPECT_EQ(SshMessageType::ServiceAccept, visitor());

  KexInitMessage kex_init_msg;
  msg = kex_init_msg;
  EXPECT_EQ(SshMessageType::KexInit, visitor());

  KexEcdhInitMessage kex_ecdh_init_msg;
  msg = kex_ecdh_init_msg;
  EXPECT_EQ(SshMessageType::KexECDHInit, visitor());

  UserAuthPubKeyOkMsg user_auth_pubkey_ok_msg;
  msg = user_auth_pubkey_ok_msg;
  EXPECT_EQ(SshMessageType::UserAuthPubKeyOk, visitor());

  msg.reset();
  EXPECT_FALSE(msg.message.oneof.has_value());
  EXPECT_EQ(SshMessageType(0), visitor());
};

constexpr int overload(ChannelRequestMsg& _) {
  return 0;
}

constexpr int overload(ChannelMsg auto& _) {
  return 1;
}

constexpr int overload(auto& _) {
  return 2;
}

constexpr int overload(const ChannelRequestMsg& _) {
  return 3;
}

TEST(MessagesTest, Message_Visit_ConceptArgs) {
  auto visitor = [](const Message& msg) {
    return msg.visit(
      [&](ChannelMsg auto& _) {
        return 0;
      },
      [](auto&) {
        return 1;
      });
  };

  ChannelDataMsg channel_data_msg;
  ChannelRequestMsg channel_request_msg;
  KexInitMessage kex_init_msg;
  EXPECT_STATIC_ASSERT(overload(channel_request_msg) == 0);
  EXPECT_STATIC_ASSERT(overload(channel_data_msg) == 1);
  EXPECT_STATIC_ASSERT(overload(kex_init_msg) == 2);
  EXPECT_STATIC_ASSERT(overload(std::as_const(channel_request_msg)) == 3);
  EXPECT_STATIC_ASSERT(overload(std::as_const(channel_data_msg)) == 1);
  EXPECT_STATIC_ASSERT(overload(std::as_const(kex_init_msg)) == 2);
  Message msg;
  msg = channel_data_msg;
  EXPECT_EQ(0, visitor(msg));
  msg = channel_request_msg;
  EXPECT_EQ(0, visitor(msg));
  msg = kex_init_msg;
  EXPECT_EQ(1, visitor(msg));
}

TEST(MessagesTest, Message_RoundTrip) {
  wire::ExtInfoMsg extInfo;
  wire::PingExtension pingExt;
  pingExt.version = "0";
  extInfo.extensions->emplace_back(std::move(pingExt));

  wire::Message msg = extInfo; // copy

  Envoy::Buffer::OwnedImpl tmp;
  auto n = msg.encode(tmp);
  EXPECT_TRUE(n.ok());
  auto encoded1 = tmp.toString();

  wire::Message decoded;
  auto n2 = decoded.decode(tmp, *n);
  EXPECT_TRUE(n2.ok());
  EXPECT_EQ(*n, *n2);

  EXPECT_TRUE(decoded.message.holds_alternative<ExtInfoMsg>());

  EXPECT_EQ(extInfo.extensions->size(), decoded.message.get<ExtInfoMsg>().extensions->size());
  EXPECT_EQ(extInfo.extensions[0].extension_name(), decoded.message.get<ExtInfoMsg>().extensions[0].extension_name());
  EXPECT_EQ(extInfo.extensions[0].extension.get<PingExtension>().version, decoded.message.get<ExtInfoMsg>().extensions[0].extension.get<PingExtension>().version);

  EXPECT_EQ(encoded1, *encodeTo<std::string>(decoded));
}

TEST(MessagesTest, Message_CopyMove) {
  wire::Message m1;
  wire::ChannelDataMsg data;
  data.recipient_channel = 1;
  data.data->resize(100);
  auto data_ptr = data.data->data();
  m1.message.reset(std::move(data));

  // move
  wire::Message m2{std::move(m1)};
  // a moved-from optional with a value will still have a value, and the variant will still contain
  // a ChannelDataMsg, but non-trivially-movable fields (such as the data byte array) will become
  // empty in the moved-from message.
  EXPECT_TRUE(m1.message.oneof.has_value());                               // trivial move (copy)
  EXPECT_EQ(m1.msg_type(), wire::SshMessageType::ChannelData);             // trivial move (copy)
  EXPECT_EQ(1, *m1.message.get<wire::ChannelDataMsg>().recipient_channel); // trivial move (copy)
  EXPECT_TRUE(m1.message.get<wire::ChannelDataMsg>().data->empty());       // move

  EXPECT_TRUE(m2.message.oneof.has_value());                                // trivial move (copy)
  EXPECT_EQ(m2.msg_type(), wire::SshMessageType::ChannelData);              // trivial move (copy)
  EXPECT_EQ(1, *m2.message.get<wire::ChannelDataMsg>().recipient_channel);  // trivial move (copy)
  EXPECT_EQ(m2.message.get<wire::ChannelDataMsg>().data->data(), data_ptr); // move

  // copy
  wire::Message m3{m2};
  EXPECT_TRUE(m3.message.oneof.has_value());
  EXPECT_EQ(m3.msg_type(), wire::SshMessageType::ChannelData);
  EXPECT_EQ(1, *m3.message.get<wire::ChannelDataMsg>().recipient_channel);
  EXPECT_NE(m3.message.get<wire::ChannelDataMsg>().data->data(), data_ptr);
  EXPECT_EQ(m3.message.get<wire::ChannelDataMsg>().data, m2.message.get<wire::ChannelDataMsg>().data);
}

template <typename T>
class TopLevelMessagesTestSuite : public testing::Test {
public:
};

template <typename... Args>
struct topLevelMsgsHelper;

template <typename... Args>
struct topLevelMsgsHelper<sub_message<Args...>> : std::type_identity<::testing::Types<Args...>> {};

using topLevelMsgs = typename topLevelMsgsHelper<wire::detail::top_level_message>::type;

// TYPED_TEST_SUITE(TopLevelMessagesTestSuite, testing::Types<KexInitMessage>);
TYPED_TEST_SUITE(TopLevelMessagesTestSuite, topLevelMsgs);

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
TEST_FIELDS(KexInitMessage,
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
TEST_FIELDS(KexEcdhInitMessage,
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

template <>
struct detail::random_value_impl<wire::Extension> {
  static constexpr auto operator()() {
    wire::Extension ext;
    test_field_reflect<wire::Extension>::visit_fields(ext, [](auto&& field) {
      test_field_reflect<std::decay_t<decltype(field)>>::visit_fields(field, [](auto&& field) {
        test_field_reflect<std::decay_t<decltype(field)>>::visit_fields(field, [](auto&& field) {
          field = random_value<typename std::decay_t<decltype(field)>::value_type>();
        });
      });
    });
    return ext;
  }
};
template <>
struct detail::random_value_impl<UserAuthInfoPrompt> {
  static constexpr auto operator()() {
    UserAuthInfoPrompt ext;
    test_field_reflect<UserAuthInfoPrompt>::visit_fields(ext, [](auto&& field) {
      test_field_reflect<std::decay_t<decltype(field)>>::visit_fields(field, [](auto&& field) {
        test_field_reflect<std::decay_t<decltype(field)>>::visit_fields(field, [](auto&& field) {
          field = random_value<typename std::decay_t<decltype(field)>::value_type>();
        });
      });
    });
    return ext;
  }
};

TYPED_TEST(TopLevelMessagesTestSuite, RoundTrip) {
  for (auto i = 0; i < 1000; i++) {
    TypeParam msg;
    test_field_reflect<TypeParam>::visit_fields(msg, [](auto&& field) {
      test_field_reflect<std::decay_t<decltype(field)>>::visit_fields(field, [](auto&& field) {
        test_field_reflect<std::decay_t<decltype(field)>>::visit_fields(field, [](auto&& field) {
          using field_type = std::decay_t<decltype(field)>;
          field = random_value<typename field_type::value_type>();
          if constexpr ((field_type::encoding_options & CommaDelimited) != 0) {
            // remove empty elements
            field.value.erase(std::remove_if(field.value.begin(), field.value.end(),
                                             [](const auto& elem) { return elem.empty(); }),
                              field.value.end());
          }
        });
      });
    });

    size_t overload_index{};
    std::string global_request_success_key{};
    if constexpr (wire::detail::is_overloaded_message_v<TypeParam>) {
      overload_index = msg.messageForTest().key_field();
    }
    if constexpr (std::is_same_v<TypeParam, wire::GlobalRequestSuccessMsg>) {
      global_request_success_key = msg.response.key_field();
    }
    Envoy::Buffer::OwnedImpl buffer;
    auto r = msg.encode(buffer);
    EXPECT_TRUE(r.ok()) << r.status().ToString();

    TypeParam decoded;
    r = decoded.decode(buffer, buffer.length());
    EXPECT_TRUE(r.ok()) << r.status().ToString();
    EXPECT_EQ(decoded, msg);

    if constexpr (wire::detail::is_overloaded_message_v<TypeParam>) {
      decoded.messageForTest().key_field() = overload_index;
      auto r = decoded.messageForTest().decodeUnknown();
      EXPECT_TRUE(r.ok()) << r.status().ToString();
    }
    if constexpr (std::is_same_v<TypeParam, wire::GlobalRequestSuccessMsg>) {
      decoded.response.key_field() = global_request_success_key;
      auto r = decoded.response.decodeUnknown();
      EXPECT_TRUE(r.ok()) << r.status().ToString();
    }
  }
}

TYPED_TEST(TopLevelMessagesTestSuite, MessageType) {
  TypeParam msg;
  EXPECT_EQ(TypeParam::type, msg.msg_type());
}

TEST(NonstandardMessagesTest, GlobalRequestSuccessMsg_DecodeErrors) {
  Buffer::OwnedImpl buffer;
  GlobalRequestSuccessMsg msg;
  auto r = msg.decode(buffer, 1);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ("short read", r.status().message());

  write(buffer, GlobalRequestSuccessMsg::type);
  msg.response.key_field() = std::string(HostKeysProveResponseMsg::submsg_key);
  write(buffer, static_cast<uint32_t>(1));
  // the only way this can fail is if the key field is set manually before decoding, then an
  // invalid message is decoded
  r = msg.decode(buffer, buffer.length());
  EXPECT_FALSE(r.ok());
  EXPECT_EQ("short read", r.status().message());
}

TEST(NonstandardMessagesTest, GlobalRequestSuccessMsg_EncodeErrors) {
  Buffer::OwnedImpl buffer;
  GlobalRequestSuccessMsg msg;
  auto resp = HostKeysProveResponseMsg{};
  bytes big_data;
  big_data.resize(wire::MaxPacketSize + 1);
  resp.signatures = {std::move(big_data)};
  msg.response = std::move(resp);
  auto r = msg.encode(buffer);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ("message size too large", r.status().message());
}

TEST(NonstandardMessagesTest, PubKeyUserAuthRequestMsg_DecodeErrors) {
  {
    Buffer::OwnedImpl buffer;
    write(buffer, true);
    write_opt<LengthPrefixed>(buffer, to_bytes("foo"sv));
    write_opt<LengthPrefixed>(buffer, to_bytes("bar"sv));
    write(buffer, static_cast<uint8_t>(1));
    write(buffer, static_cast<uint8_t>(1));
    PubKeyUserAuthRequestMsg msg;
    auto r = msg.decode(buffer, buffer.length());
    EXPECT_FALSE(r.ok());
    EXPECT_EQ("buffer underflow", r.status().message());
  }
  {
    Buffer::OwnedImpl buffer;
    write(buffer, false);
    write_opt<LengthPrefixed>(buffer, to_bytes("foo"sv));
    write_opt<LengthPrefixed>(buffer, to_bytes("bar"sv));
    write_opt<LengthPrefixed>(buffer, to_bytes("baz"sv));
    PubKeyUserAuthRequestMsg msg;
    auto r = msg.decode(buffer, buffer.length());
    EXPECT_TRUE(r.ok());
  }
}

TEST(NonstandardMessagesTest, PubKeyUserAuthRequestMsg_EncodeErrors) {
  PubKeyUserAuthRequestMsg msg;
  bytes big_data;
  big_data.resize(wire::MaxPacketSize + 1);
  msg.public_key = std::move(big_data);
  Buffer::OwnedImpl buffer;
  auto r = msg.encode(buffer);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ("message size too large", r.status().message());
}

TEST(NonstandardMessagesTest, UserAuthInfoPrompt_ReadErrors) {
  UserAuthInfoPrompt prompt;
  Buffer::OwnedImpl buffer;
  EXPECT_THROW_WITH_MESSAGE(read(buffer, prompt, 1),
                            EnvoyException,
                            "error decoding UserAuthInfoPrompt: short read");
}

TEST(NonstandardMessagesTest, UserAuthInfoPrompt_WriteErrors) {
  UserAuthInfoPrompt prompt;
  prompt.prompt->resize(MaxPacketSize + 1);
  Buffer::OwnedImpl buffer;
  EXPECT_THROW_WITH_MESSAGE(write(buffer, prompt),
                            EnvoyException,
                            "error encoding UserAuthInfoPrompt: message size too large");
}

TEST(NonstandardMessagesTest, Extension_ReadErrors) {
  {
    Extension ext;
    Buffer::OwnedImpl buffer;
    EXPECT_THROW_WITH_MESSAGE(read(buffer, ext, 1),
                              EnvoyException,
                              "error decoding extension name: Invalid Argument: short read");
  }
  {
    Extension ext;
    Buffer::OwnedImpl buffer;
    write_opt<LengthPrefixed>(buffer, "example"s);
    write(buffer, static_cast<uint32_t>(1000));
    EXPECT_THROW_WITH_MESSAGE(read(buffer, ext, buffer.length()),
                              EnvoyException,
                              "error decoding extension: invalid message length: 1004");
  }
  {
    Extension ext;
    Buffer::OwnedImpl buffer;
    write_opt<LengthPrefixed>(buffer, "server-sig-algs"s);
    write_opt<LengthPrefixed>(buffer, ",,,"s);
    write_opt<LengthPrefixed>(buffer, "0"s);
    EXPECT_THROW_WITH_MESSAGE(read(buffer, ext, buffer.length()),
                              EnvoyException,
                              "error decoding extension: Invalid Argument: invalid empty string in comma-separated list");
  }
}

TEST(NonstandardMessagesTest, Extension_WriteErrors) {
  Buffer::OwnedImpl buffer;
  Extension ext;
  PingExtension ping;
  std::string big_data;
  big_data.resize(MaxPacketSize + 1);
  ping.version = std::move(big_data);
  ext.extension = std::move(ping);
  EXPECT_THROW_WITH_MESSAGE(write(buffer, ext),
                            EnvoyException,
                            "error encoding extension: Aborted: message size too large");
}

TEST(OverloadedMessageTest, Resolve) {
  Buffer::OwnedImpl buffer;
  UserAuthPubKeyOkMsg overload;
  overload.public_key = random_value<bytes>();
  auto r = overload.encode(buffer);
  EXPECT_TRUE(r.ok());

  OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg> msg;
  r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok());

  auto ref = msg.resolve<UserAuthPubKeyOkMsg>();
  EXPECT_TRUE(ref.has_value());
  EXPECT_EQ(overload, ref.value());
}

TEST(OverloadedMessageTest, Resolve_WrongType) {
  Buffer::OwnedImpl buffer;
  UserAuthPubKeyOkMsg overload;
  auto r = overload.encode(buffer);
  EXPECT_TRUE(r.ok());

  OverloadedMessage<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg> msg;
  r = msg.decode(buffer, buffer.length());
  EXPECT_TRUE(r.ok());

  // This won't *necessarily* always fail; it depends on whether one message can be interpreted
  // as a different type without decoding errors.
  auto ref = msg.resolve<UserAuthInfoRequestMsg>();
  EXPECT_FALSE(ref.has_value());
}

TEST(KeyFieldAccessorsTest, KeyFields) {
  {
    UserAuthRequestMsg msg;
    msg.request = PubKeyUserAuthRequestMsg{};
    EXPECT_EQ(PubKeyUserAuthRequestMsg::submsg_key, msg.method_name());
    msg.request = KeyboardInteractiveUserAuthRequestMsg{};
    EXPECT_EQ(KeyboardInteractiveUserAuthRequestMsg::submsg_key, msg.method_name());
    msg.request = NoneAuthRequestMsg{};
    EXPECT_EQ(NoneAuthRequestMsg::submsg_key, msg.method_name());
  }
  {
    ChannelRequestMsg msg;
    msg.request = PtyReqChannelRequestMsg{};
    EXPECT_EQ(PtyReqChannelRequestMsg::submsg_key, msg.request_type());
    msg.request = ShellChannelRequestMsg{};
    EXPECT_EQ(ShellChannelRequestMsg::submsg_key, msg.request_type());
    msg.request = WindowDimensionChangeChannelRequestMsg{};
    EXPECT_EQ(WindowDimensionChangeChannelRequestMsg::submsg_key, msg.request_type());
  }
  {
    GlobalRequestMsg msg;
    msg.request = HostKeysProveRequestMsg{};
    EXPECT_EQ(HostKeysProveRequestMsg::submsg_key, msg.request_name());
    msg.request = HostKeysMsg{};
    EXPECT_EQ(HostKeysMsg::submsg_key, msg.request_name());
  }
  {
    Extension msg;
    msg.extension.reset(ServerSigAlgsExtension{});
    EXPECT_EQ(ServerSigAlgsExtension::submsg_key, msg.extension_name());
    msg.extension.reset(PingExtension{});
    EXPECT_EQ(PingExtension::submsg_key, msg.extension_name());
  }
}

} // namespace wire::test