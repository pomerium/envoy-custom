#pragma once

#include "source/extensions/filters/network/ssh/stream_tracker.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;

class ConnectionService : public virtual Service {
public:
  std::string name() override { return "ssh-connection"; };
  ConnectionService(TransportCallbacks& callbacks, Api::Api& api);

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;
};

class DownstreamConnectionService final : public ConnectionService,
                                          public ChannelStreamCallbacks,
                                          public Logger::Loggable<Logger::Id::filter> {
public:
  DownstreamConnectionService(TransportCallbacks& callbacks,
                              Api::Api& api,
                              std::shared_ptr<StreamTracker> stream_tracker);

  absl::Status onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) override;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;

  void onStreamBegin(Network::Connection& connection, std::shared_ptr<StreamCallbacks> callbacks);
  void onStreamEnd();

private:
  DownstreamTransportCallbacks& transport_;

  std::shared_ptr<StreamTracker> stream_tracker_;
  std::unique_ptr<StreamHandle> stream_handle_;
};

class UpstreamConnectionService final : public ConnectionService,
                                        public UpstreamService,
                                        public Logger::Loggable<Logger::Id::filter> {
public:
  UpstreamConnectionService(
    UpstreamTransportCallbacks& callbacks,
    Api::Api& api)
      : ConnectionService(callbacks, api) {}
  absl::Status requestService() override;
  absl::Status onServiceAccepted() override;

  absl::Status handleMessage(wire::Message&& msg) override;
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;

private:
  MessageDispatcher<wire::Message>* msg_dispatcher_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec