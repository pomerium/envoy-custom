#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/message_traits.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

#include "test/test_common/test_common.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"

namespace wire::test {

TEST(MessagesTest, Message_Visit) {
  Message msg;

  auto non_overload = [&](const DisconnectMsg& _) {
    return SshMessageType::Disconnect;
  };
  auto overload = [&](opt_ref<const KexEcdhInitMsg> _) {
    return SshMessageType::KexInit;
  };
  auto defaultCase = [&](auto&) {
    return SshMessageType::KexInit;
  };

  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(overload)>::arg_type_with_cv_optref,
                                      opt_ref<const KexEcdhInitMsg>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<callable_info_t<decltype(overload)>::arg_type,
                                      KexEcdhInitMsg>);
  EXPECT_STATIC_ASSERT(wire::detail::is_top_level_message_v<KexEcdhInitMsg>);
  EXPECT_STATIC_ASSERT(wire::detail::is_top_level_message_v<DisconnectMsg>);

  EXPECT_STATIC_ASSERT(std::is_same_v<callable_arg_type_t<decltype(overload)>,
                                      KexEcdhInitMsg>);
  EXPECT_STATIC_ASSERT(wire::detail::is_overloaded_message<callable_arg_type_t<decltype(overload)>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<wire::detail::overload_set_for_t<callable_arg_type_t<decltype(overload)>>,
                                      OverloadSet<KexEcdhInitMsg>>);
  EXPECT_STATIC_ASSERT(!wire::detail::top_level_visitor<false, decltype(overload)>::is_catchall_visitor);

  EXPECT_STATIC_ASSERT(std::is_same_v<callable_arg_type_t<decltype(non_overload)>,
                                      DisconnectMsg>);
  EXPECT_STATIC_ASSERT(!wire::detail::is_overloaded_message<callable_arg_type_t<decltype(non_overload)>>);
  EXPECT_STATIC_ASSERT(std::is_same_v<wire::detail::overload_set_for_t<callable_arg_type_t<decltype(non_overload)>>,
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
      [&](const KexInitMsg& _) {
        return SshMessageType::KexInit;
      },
      [&](opt_ref<const KexEcdhInitMsg> _) {
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

  KexInitMsg kex_init_msg;
  msg = kex_init_msg;
  EXPECT_EQ(SshMessageType::KexInit, visitor());

  KexEcdhInitMsg kex_ecdh_init_msg;
  msg = kex_ecdh_init_msg;
  EXPECT_EQ(SshMessageType::KexECDHInit, visitor());

  UserAuthPubKeyOkMsg user_auth_pubkey_ok_msg;
  msg = user_auth_pubkey_ok_msg;
  EXPECT_EQ(SshMessageType::UserAuthPubKeyOk, visitor());

  msg.reset();
  EXPECT_FALSE(msg.has_value());
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
  KexInitMsg kex_init_msg;
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
  EXPECT_FALSE(extInfo.hasExtension<PingExtension>());
  extInfo.extensions->emplace_back(std::move(pingExt));
  EXPECT_TRUE(extInfo.hasExtension<PingExtension>());
  EXPECT_FALSE(extInfo.hasExtension<ServerSigAlgsExtension>());

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
  EXPECT_EQ(msg, decoded);

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
  EXPECT_TRUE(m1.has_value());
  // move
  wire::Message m2{std::move(m1)};
  // a moved-from optional with a value will still have a value, and the variant will still contain
  // a ChannelDataMsg, but non-trivially-movable fields (such as the data byte array) will become
  // empty in the moved-from message.
  EXPECT_TRUE(m1.has_value());                                             // trivial move (copy)
  EXPECT_EQ(m1.msg_type(), wire::SshMessageType::ChannelData);             // trivial move (copy)
  EXPECT_EQ(1, *m1.message.get<wire::ChannelDataMsg>().recipient_channel); // trivial move (copy)
  EXPECT_TRUE(m1.message.get<wire::ChannelDataMsg>().data->empty());       // move

  EXPECT_TRUE(m2.has_value());                                              // trivial move (copy)
  EXPECT_EQ(m2.msg_type(), wire::SshMessageType::ChannelData);              // trivial move (copy)
  EXPECT_EQ(1, *m2.message.get<wire::ChannelDataMsg>().recipient_channel);  // trivial move (copy)
  EXPECT_EQ(m2.message.get<wire::ChannelDataMsg>().data->data(), data_ptr); // move

  // copy
  wire::Message m3{m2};
  EXPECT_EQ(m2, m3);
  EXPECT_TRUE(m3.has_value());
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

TYPED_TEST(TopLevelMessagesTestSuite, RoundTrip) {
  for (auto i = 0; i < 1000; i++) {
    TypeParam msg;
    populateFields(msg);

    size_t overload_index{};
    std::string global_request_success_key{};
    if constexpr (wire::detail::is_overload_set_v<TypeParam>) {
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

    if constexpr (wire::detail::is_overload_set_v<TypeParam>) {
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

  OverloadSet<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg> msg;
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

  OverloadSet<UserAuthPubKeyOkMsg, UserAuthInfoRequestMsg> msg;
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

TEST(MessageFormatting, TestMessageFormatting) {
  EXPECT_EQ(type_name<void>(), "void");
  KexInitMsg m;
  m.cookie = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  m.kex_algorithms = {"a", "b"};
  m.server_host_key_algorithms = {"c", "d"};
  m.encryption_algorithms_client_to_server = {"e", "f"};
  m.encryption_algorithms_server_to_client = {"g", "h"};
  m.mac_algorithms_client_to_server = {"i", "j"};
  m.mac_algorithms_server_to_client = {"k", "l"};
  m.compression_algorithms_client_to_server = {"m", "n"};
  m.compression_algorithms_server_to_client = {"o", "p"};
  m.languages_client_to_server = {"q", "r"};
  m.languages_server_to_client = {"s", "t"};
  m.first_kex_packet_follows = false;
  m.reserved = 0;

  EXPECT_EQ(
    R"(
KexInitMsg:
  cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
  kex_algorithms: ["a", "b"]
  server_host_key_algorithms: ["c", "d"]
  encryption_algorithms_client_to_server: ["e", "f"]
  encryption_algorithms_server_to_client: ["g", "h"]
  mac_algorithms_client_to_server: ["i", "j"]
  mac_algorithms_server_to_client: ["k", "l"]
  compression_algorithms_client_to_server: ["m", "n"]
  compression_algorithms_server_to_client: ["o", "p"]
  languages_client_to_server: ["q", "r"]
  languages_server_to_client: ["s", "t"]
  first_kex_packet_follows: false
  reserved: 0
)"sv.substr(1),
    testing::PrintToString(m));

  EXPECT_EQ(R"(["a", "b"])"s, testing::PrintToString(m.kex_algorithms));

  EXPECT_THAT(m, Field(&KexInitMsg::kex_algorithms, Eq(string_list{"a", "b"})));
}

} // namespace wire::test