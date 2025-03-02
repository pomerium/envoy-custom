#include "source/extensions/filters/network/ssh/wire/wire_test.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/common.h"

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

  static_assert(std::is_same_v<detail::visitor_arg_type_t<decltype(overload)>, KexEcdhInitMessage>);
  static_assert(detail::is_overload<detail::visitor_arg_type_t<decltype(overload)>>);
  static_assert(std::is_same_v<detail::overload_for_t<detail::visitor_arg_type_t<decltype(overload)>>, OverloadedMessage<KexEcdhInitMessage>>);
  static_assert(detail::single_visitor<decltype(overload)>::selected_overload);

  static_assert(std::is_same_v<detail::visitor_arg_type_t<decltype(non_overload)>, DisconnectMsg>);
  static_assert(!detail::is_overload<detail::visitor_arg_type_t<decltype(non_overload)>>);
  static_assert(std::is_same_v<detail::overload_for_t<detail::visitor_arg_type_t<decltype(non_overload)>>, DisconnectMsg>);
  static_assert(!detail::single_visitor<decltype(non_overload)>::selected_overload);

  static_assert(!detail::single_visitor<decltype(defaultCase)>::selected_overload);

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
        return SshMessageType::KexECDHInit;
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
};

} // namespace wire::test