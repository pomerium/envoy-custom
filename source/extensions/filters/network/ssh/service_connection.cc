#include "source/extensions/filters/network/ssh/service_connection.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

ConnectionService::ConnectionService(
  TransportCallbacks& callbacks,
  Api::Api& api,
  Peer direction)
    : transport_(callbacks),
      api_(api),
      local_peer_(direction) {
  (void)api_;
}

void ConnectionService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  msg_dispatcher_ = dispatcher;
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpen, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpenConfirmation, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelOpenFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelWindowAdjust, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelData, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelExtendedData, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelEOF, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelClose, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::ChannelFailure, this);
}

DownstreamConnectionService::DownstreamConnectionService(TransportCallbacks& callbacks,
                                                         Api::Api& api,
                                                         std::shared_ptr<StreamTracker> stream_tracker)
    : ConnectionService(callbacks, api, Peer::Downstream),
      transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)),
      stream_tracker_(std::move(stream_tracker)) {}

void DownstreamConnectionService::onStreamBegin(Network::Connection& connection) {
  ASSERT(connection.dispatcher().isThreadSafe());

  stream_handle_ = stream_tracker_->onStreamBegin(transport_.streamId(), connection, *this, *this);
}

void DownstreamConnectionService::onStreamEnd() {
  stream_handle_.reset();
}

absl::Status UpstreamConnectionService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(std::move(req)).status();
}

absl::Status UpstreamConnectionService::onServiceAccepted() {
  return absl::OkStatus();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec