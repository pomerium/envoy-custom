#pragma once

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/multiplexer.h"
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
                              std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr)
      : ConnectionService(callbacks, api),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)),
        slot_ptr_(slot_ptr) {}

  absl::Status onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) override;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status onStreamBegin(const AuthState& auth_state, Dispatcher& dispatcher);
  void onStreamEnd();

private:
  DownstreamTransportCallbacks& transport_;
  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr_;
  std::shared_ptr<SourceDownstreamSessionMultiplexer> source_multiplexer_;
  std::shared_ptr<MirrorSessionMultiplexer> mirror_multiplexer_;
};

class UpstreamConnectionService final : public ConnectionService,
                                        public UpstreamService,
                                        public Logger::Loggable<Logger::Id::filter> {
public:
  UpstreamConnectionService(
    UpstreamTransportCallbacks& callbacks,
    Api::Api& api,
    std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr)
      : ConnectionService(callbacks, api),
        slot_ptr_(slot_ptr) {}
  absl::Status requestService() override;
  absl::Status onServiceAccepted() override;

  absl::Status handleMessage(wire::Message&& msg) override;
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status onStreamBegin(const AuthState& auth_state, Dispatcher& dispatcher);
  void onStreamEnd();

private:
  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr_;
  std::shared_ptr<SourceUpstreamSessionMultiplexer> source_multiplexer_;

  MessageDispatcher<wire::Message>* msg_dispatcher_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec