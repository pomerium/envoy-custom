#include "source/extensions/filters/network/ssh/wire/wire_test_common.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/common.h"
#include <memory>

namespace wire::test {

TEST(MessageTest, Visit) {
  Message msg;

  auto non_overload = [&](const DisconnectMsg& _) {
    return SshMessageType::Disconnect;
  };
  auto overload = [&](Envoy::OptRef<const KexEcdhInitMessage> _) {
    return SshMessageType::KexInit;
  };
  auto defaultCase = [&](auto&) {
    return SshMessageType::KexInit;
  };

  static_assert(std::is_same_v<detail::visitor_info_t<decltype(overload)>::arg_type_with_cv_optref, Envoy::OptRef<const KexEcdhInitMessage>>);
  static_assert(std::is_same_v<detail::visitor_info_t<decltype(overload)>::arg_type, KexEcdhInitMessage>);
  static_assert(detail::is_top_level_message_v<KexEcdhInitMessage>);
  static_assert(detail::is_top_level_message_v<DisconnectMsg>);

  static_assert(std::is_same_v<detail::visitor_arg_type_t<decltype(overload)>, KexEcdhInitMessage>);
  static_assert(detail::is_overload<detail::visitor_arg_type_t<decltype(overload)>>);
  static_assert(std::is_same_v<detail::overload_for_t<detail::visitor_arg_type_t<decltype(overload)>>, OverloadedMessage<KexEcdhInitMessage>>);
  static_assert(detail::single_top_level_visitor<false, decltype(overload)>::selected_overload);

  static_assert(std::is_same_v<detail::visitor_arg_type_t<decltype(non_overload)>, DisconnectMsg>);
  static_assert(!detail::is_overload<detail::visitor_arg_type_t<decltype(non_overload)>>);
  static_assert(std::is_same_v<detail::overload_for_t<detail::visitor_arg_type_t<decltype(non_overload)>>, DisconnectMsg>);
  static_assert(!detail::single_top_level_visitor<false, decltype(non_overload)>::selected_overload);

  static_assert(!detail::single_top_level_visitor<false, decltype(defaultCase)>::selected_overload);

  static_assert(std::is_invocable_v<decltype([](any_of<wire::IgnoreMsg, wire::DebugMsg, wire::UnimplementedMsg> auto&) {}),
                                    wire::IgnoreMsg&>);
  static_assert(std::is_invocable_v<decltype([](wire::detail::TopLevelMessage auto&) {}),
                                    wire::IgnoreMsg&>);

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
      [&](Envoy::OptRef<const KexEcdhInitMessage> _) {
        return SshMessageType::KexECDHInit;
      },
      [&](Envoy::OptRef<const UserAuthPubKeyOkMsg> _) {
        return SshMessageType::UserAuthPubKeyOk;
      },
      [&](const auto&) {
        return SshMessageType::Invalid;
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

TEST(MessageTest, Visit_ConceptArgs) {
  auto visitor = [](const Message& msg) constexpr {
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
  static_assert(overload(channel_request_msg) == 0);
  static_assert(overload(channel_data_msg) == 1);
  static_assert(overload(kex_init_msg) == 2);
  static_assert(overload(std::as_const(channel_request_msg)) == 3);
  static_assert(overload(std::as_const(channel_data_msg)) == 1);
  static_assert(overload(std::as_const(kex_init_msg)) == 2);
  Message msg;
  msg = channel_data_msg;
  EXPECT_EQ(0, visitor(msg));
  msg = channel_request_msg;
  EXPECT_EQ(0, visitor(msg));
  msg = kex_init_msg;
  EXPECT_EQ(1, visitor(msg));
}

TEST(MessageTest, RoundTrip) {
  wire::ExtInfoMsg extInfo;
  wire::PingExtension pingExt;
  pingExt.version = "0";
  extInfo.extensions->emplace_back(std::move(pingExt));

  Envoy::Buffer::OwnedImpl tmp;
  auto n = extInfo.encode(tmp);
  EXPECT_TRUE(n.ok());
  auto encoded1 = tmp.toString();

  wire::ExtInfoMsg decoded;
  auto n2 = decoded.decode(tmp, *n);
  EXPECT_TRUE(n2.ok());
  EXPECT_EQ(*n, *n2);

  EXPECT_EQ(extInfo.extensions->size(), decoded.extensions->size());
  EXPECT_EQ(extInfo.extensions[0].extension_name(), decoded.extensions[0].extension_name());
  EXPECT_EQ(extInfo.extensions[0].extension.get<PingExtension>().version, decoded.extensions[0].extension.get<PingExtension>().version);

  EXPECT_EQ(encoded1, *encodeTo<std::string>(decoded));
}

TEST(MessageTest, CopyMove) {
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

} // namespace wire::test