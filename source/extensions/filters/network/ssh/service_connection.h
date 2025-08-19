#pragma once

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/shared.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/common/http/utility.h"

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
                              std::shared_ptr<ActiveStreamTracker> active_stream_tracker)
      : ConnectionService(callbacks, api),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)),
        active_stream_tracker_(std::move(active_stream_tracker)) {}

  absl::Status onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) override;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  void onStreamBegin(Network::Connection& connection, std::shared_ptr<ActiveStreamCallbacks> callbacks);
  void onStreamEnd();

  struct RequestOpenDownstreamChannelHandler final : public SshMessageMiddleware {
    explicit RequestOpenDownstreamChannelHandler(DownstreamConnectionService& self, uint32_t our_id, Network::IoHandlePtr io_handle,
                                                 StreamInfo::FilterStateImpl passthrough_filter_state)
        : self(self),
          our_id_(our_id),
          io_handle_(std::move(io_handle)),
          passthrough_filter_state_(std::move(passthrough_filter_state)) {}
    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override {
      return msg.visit(
        [&](wire::ChannelOpenConfirmationMsg& msg) -> absl::StatusOr<MiddlewareResult> {
          if (*msg.recipient_channel != our_id_) {
            return MiddlewareResult::Continue; // not our channel
          }
          self.onDownstreamChannelOpened(msg, std::move(io_handle_), std::move(passthrough_filter_state_));
          return MiddlewareResult::Break | MiddlewareResult::UninstallSelf;
        },
        [&](wire::ChannelOpenFailureMsg& msg) -> absl::StatusOr<MiddlewareResult> {
          if (*msg.recipient_channel != our_id_) {
            return MiddlewareResult::Continue; // not our channel
          }
          return absl::InvalidArgumentError(fmt::format("failed to open channel: {}", *msg.description));
        },
        [&](auto&) -> absl::StatusOr<MiddlewareResult> {
          return MiddlewareResult::Continue;
        });
    }
    DownstreamConnectionService& self;
    uint32_t our_id_;
    Network::IoHandlePtr io_handle_;
    StreamInfo::FilterStateImpl passthrough_filter_state_;
  };

  void requestOpenDownstreamChannel(Network::IoHandlePtr io_handle) {
    auto passthroughState = std::static_pointer_cast<IoSocket::UserSpace::PassthroughStateImpl>(dynamic_cast<IoSocket::UserSpace::IoHandleImpl&>(*io_handle)
                                                                                                  .passthroughState());
    envoy::config::core::v3::Metadata passthrough_metadata;
    StreamInfo::FilterStateImpl passthrough_filter_state{StreamInfo::FilterState::LifeSpan::Connection};

    passthroughState->mergeInto(passthrough_metadata, passthrough_filter_state);

    auto serverName = passthrough_filter_state.getDataReadOnly<RequestedServerName>(RequestedServerName::key());
    ASSERT(serverName != nullptr);

    auto downstreamAddr = passthrough_filter_state.getDataReadOnly<Network::AddressObject>(DownstreamSourceAddressFilterStateFactory::key());
    ASSERT(downstreamAddr != nullptr);

    wire::ChannelOpenMsg open;
    open.channel_type = "forwarded-tcpip";
    auto newId = external_channel_ids_++; // todo
    open.sender_channel = newId;
    open.initial_window_size = 2097152;
    open.max_packet_size = 32768;
    Buffer::OwnedImpl extra;
    auto addrData = Envoy::Http::Utility::parseAuthority(serverName->value());
    wire::write_opt<wire::LengthPrefixed>(extra, std::string(addrData.host_));
    wire::write<uint32_t>(extra, 443);
    wire::write_opt<wire::LengthPrefixed>(extra, downstreamAddr->address()->ip()->addressAsString());
    wire::write<uint32_t>(extra, downstreamAddr->address()->ip()->port());
    open.extra = wire::flushTo<bytes>(extra);
    auto r = transport_.sendMessageToConnection(std::move(open));
    if (!r.ok()) {
      ENVOY_LOG(error, "error requesting downstream channel: {}", statusToString(r.status()));
      io_handle->close(); // todo?
      return;
    }
    msg_dispatcher_->installMiddleware(&msg_handler_ext_info_.emplace(*this, newId, std::move(io_handle), std::move(passthrough_filter_state)));
  }
  void onDownstreamChannelOpened(const wire::ChannelOpenConfirmationMsg& msg, Network::IoHandlePtr io_handle, StreamInfo::FilterStateImpl passthrough_filter_state) {
    auto channel = std::make_shared<ExternalChannel>(transport_, *msg.sender_channel, test_dispatcher_, std::move(io_handle), std::move(passthrough_filter_state));
    external_channels_[*msg.recipient_channel] = channel;
    if (channel->downstreamAddress().ends_with(":0")) {
      channel->demoSendSocks5Connect();
    }
  }

  std::optional<RequestOpenDownstreamChannelHandler> msg_handler_ext_info_;
  ::Envoy::Event::Dispatcher* test_dispatcher_;

private:
  absl::Status sendToHijackedStream(wire::Message&& msg);
  absl::Status sendToExternalChannel(uint32_t channel_id, wire::Message&& msg);

  DownstreamTransportCallbacks& transport_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;
  uint32_t external_channel_ids_{100};

  absl::flat_hash_map<uint32_t, std::shared_ptr<ExternalChannel>> external_channels_;

  std::shared_ptr<ActiveStreamTracker> active_stream_tracker_;
  std::unique_ptr<ActiveStreamHandle> active_stream_handle_;
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
  // void onStreamBegin(Dispatcher& dispatcher);
  // void onStreamEnd();

private:
  MessageDispatcher<wire::Message>* msg_dispatcher_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec