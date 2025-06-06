#pragma once

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService : public virtual Service,
                        public Logger::Loggable<Logger::Id::filter> {
public:
  std::string name() override { return "ssh-userauth"; };
  UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {};

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;
};

class DownstreamUserAuthService : public UserAuthService,
                                  public StreamMgmtServerMessageHandler {
public:
  DownstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api)
      : UserAuthService(callbacks, api),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)) {}

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;

private:
  DownstreamTransportCallbacks& transport_;
};

class UpstreamUserAuthService final : public UserAuthService,
                                      public UpstreamService {
public:
  UpstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;
  absl::Status requestService() override;
  absl::Status onServiceAccepted() override;

private:
  openssh::SSHKeyPtr ca_user_key_;
  std::unique_ptr<wire::UserAuthRequestMsg> pending_req_;
  bool ext_info_received_{};
};

namespace detail {
std::pair<std::string_view, std::string_view> splitUsername(std::string_view in);
} // namespace detail

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec