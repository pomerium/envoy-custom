#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : callbacks_(callbacks), api_(api) {
  (void)callbacks_;
  (void)api_;
}

std::string UserAuthService::name() const { return "ssh-userauth"; }

absl::Status UserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::UserAuthRequest: {
    auto userAuthMsg = msg.unwrap<UserAuthRequestMsg>();

    UserAuthBannerMsg banner{};
    banner.message = "\r\n====== TEST BANNER ======" +
                     fmt::format("\r\n====== sign in as: {} ======\r\n", userAuthMsg.username);
    auto _ = callbacks_.sendMessageToConnection(banner);

    // test code
    const std::vector<absl::string_view> parts =
        absl::StrSplit(userAuthMsg.username, absl::MaxSplits("@", 1));
    auto username = parts[0];
    auto hostname = parts[1];
    callbacks_.initUpstream(username, hostname);

    return absl::OkStatus();
    // return callbacks_.downstream().sendMessage(EmptyMsg<SshMessageType::UserAuthSuccess>());
  }
  default:
    // specific protocols
    break;
  }
  return absl::OkStatus();
}

void UserAuthService::registerMessageHandlers(MessageDispatcher& dispatcher) {
  dispatcher.registerHandler(SshMessageType::UserAuthRequest, this);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec