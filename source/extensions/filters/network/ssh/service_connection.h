#pragma once

#include <cstdint>
#include <memory>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ConnectionService : public Service {
public:
  constexpr std::string name() override { return "ssh-connection"; };

  ConnectionService(TransportCallbacks& callbacks, Api::Api& api,
                    AccessLog::AccessLogFileSharedPtr access_log);
  ~ConnectionService() override {
    if (access_log_) {
      access_log_->flush();
    }
  }

  absl::Status requestService() override {
    wire::ServiceRequestMsg req;
    req.service_name = name();
    return transport_.sendMessageToConnection(req).status();
  }

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;

  AccessLog::AccessLogFileSharedPtr access_log_;
};

class DownstreamConnectionService : public ConnectionService,
                                    public ChannelStreamCallbacks,
                                    public Logger::Loggable<Logger::Id::filter> {
public:
  DownstreamConnectionService(TransportCallbacks& callbacks, Api::Api& api,
                              AccessLog::AccessLogFileSharedPtr access_log)
      : ConnectionService(callbacks, api, access_log),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)) {}

  void onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) override;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) const override;

private:
  DownstreamTransportCallbacks& transport_;
};

class UpstreamConnectionService : public ConnectionService,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  using ConnectionService::ConnectionService;
  absl::Status handleMessage(wire::Message&& msg) override;
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) const override;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec