#include "test/extensions/filters/network/ssh/ssh_upstream.h"
#include "envoy/common/exception.h"
#include "source/extensions/filters/network/ssh/id_manager.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshFakeUpstreamHandler::SshFakeUpstreamHandler(Server::Configuration::ServerFactoryContext& context,
                                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                               std::shared_ptr<SshFakeUpstreamHandlerOpts> opts)
    : TransportBase<SshFakeUpstreamHandlerCodec>(context, config, *this),
      config_(config),
      opts_(opts) {}

SshFakeUpstreamHandler::CodecCallbacks::CodecCallbacks(Network::Connection& connection)
    : connection_(connection) {}

void SshFakeUpstreamHandler::CodecCallbacks::onDecodingFailure(absl::string_view reason) {
  connection_.close(Network::ConnectionCloseType::NoFlush, reason);
}

void SshFakeUpstreamHandler::CodecCallbacks::writeToConnection(Buffer::Instance& buffer) {
  connection_.write(buffer, false);
}

Envoy::OptRef<Envoy::Network::Connection> SshFakeUpstreamHandler::CodecCallbacks::connection() {
  return connection_;
}

Network::FilterStatus SshFakeUpstreamHandler::ReadFilter::onData(Buffer::Instance& data, bool end_stream) {
  parent_.decode(data, end_stream);
  return Network::FilterStatus::StopIteration; // this is the only read filter
}

Network::FilterStatus SshFakeUpstreamHandler::ReadFilter::onNewConnection() {
  return Network::FilterStatus::Continue;
}

void SshFakeUpstreamHandler::ReadFilter::initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) {
  read_filter_callbacks_ = &callbacks;
}

SshFakeUpstreamHandler::FakeUpstreamConnectionService::FakeUpstreamConnectionService(SshFakeUpstreamHandler& parent)
    : ConnectionService(parent.config_->connection_service_options(), parent, Peer::Downstream),
      parent_(parent) {
  (void)parent_;
}

absl::Status SshFakeUpstreamHandler::FakeUpstreamConnectionService::handleMessage(wire::Message&& msg) {
  ENVOY_LOG(trace, "ssh fake upstream: received {}", msg.msg_type());

  return std::move(msg).visit(
    [&](wire::ChannelOpenMsg&& msg) {
      if (!parent_.opts_->on_channel_open_request) {
        PANIC("test bug: on_channel_open_request callback unset but required");
      }

      auto internalId = *transport_.channelIdManager()
                           .allocateNewChannel(Peer::Downstream);
      auto ok = transport_.channelIdManager()
                  .bindChannelID(internalId, PeerLocalID{
                                               .channel_id = msg.sender_channel,
                                               .local_peer = Peer::Downstream,
                                             },
                                 BindMode::PendingInternalConfirmation);
      THROW_IF_NOT_OK(ok);
      auto ch = std::make_unique<FakeUpstreamChannel>(
        internalId,
        parent_.opts_->on_channel_open_request(msg),
        parent_.opts_);
      RETURN_IF_NOT_OK(startChannel(std::move(ch), {
                                                     .allocated_channel_id = internalId,
                                                     .channel_open = msg,
                                                     .skip_auto_bind = true,
                                                   }));
      ENVOY_LOG(trace, "ssh fake upstream: started new channel {}", internalId);
      return absl::OkStatus();
    },
    [&](wire::ChannelOpenConfirmationMsg&& msg) {
      auto id = msg.recipient_channel;
      auto stat = transport_.channelIdManager().bindChannelID(id,
                                                              PeerLocalID{
                                                                .channel_id = msg.sender_channel,
                                                                .local_peer = Peer::Downstream,
                                                              },
                                                              BindMode::Confirmed);
      if (!parent_.opts_->on_channel_accepted) {
        PANIC("test bug: on_channel_accepted callback unset but required");
      }
      ENVOY_LOG(trace, "ssh fake upstream: invoking on_channel_accepted callback");
      auto ch = std::make_unique<FakeUpstreamChannel>(id, parent_.opts_->on_channel_accepted(msg), parent_.opts_);
      RETURN_IF_NOT_OK(startChannel(std::move(ch), {.allocated_channel_id = id, .skip_auto_bind = true}));
      msg.sender_channel = msg.recipient_channel;
      return channels_[id]->readMessage(std::move(msg));
    },
    [&](wire::ChannelOpenFailureMsg&& msg) {
      auto id = msg.recipient_channel;
      if (!parent_.opts_->on_channel_rejected) {
        PANIC("test bug: on_channel_rejected callback unset but required");
      }
      ENVOY_LOG(trace, "ssh fake upstream: invoking on_channel_rejected callback");
      auto ch = std::make_unique<FakeUpstreamChannel>(id, parent_.opts_->on_channel_rejected(msg), parent_.opts_);
      RETURN_IF_NOT_OK(startChannel(std::move(ch), {.allocated_channel_id = id, .skip_auto_bind = true}));
      return channels_[id]->readMessage(std::move(msg));
    },
    [&](auto&& msg) {
      return ConnectionService::handleMessage(std::move(msg)); // NOLINT(bugprone-move-forwarding-reference)
    });
};

SshFakeUpstreamHandler::FakeUpstreamUserAuthService::FakeUpstreamUserAuthService(SshFakeUpstreamHandler& parent)
    : UserAuthService(parent, parent.api_),
      parent_(parent) {}

void SshFakeUpstreamHandler::FakeUpstreamUserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::UserAuthRequest, this);
}

absl::Status SshFakeUpstreamHandler::FakeUpstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::UserAuthRequestMsg& msg) {
      ASSERT(msg.service_name == "ssh-connection");
      parent_.connection_service_->registerMessageHandlers(*parent_.msg_dispatcher_);
      return transport_.sendMessageToConnection(wire::UserAuthSuccessMsg{}).status();
    },
    [&msg](auto&) {
      return absl::InternalError(
        fmt::format("received unexpected message of type {}", msg.msg_type()));
    });
}

void SshFakeUpstreamHandler::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
  dispatcher.registerHandler(wire::SshMessageType::ServiceRequest, this);
  msg_dispatcher_ = &dispatcher;
}

absl::Status SshFakeUpstreamHandler::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::DisconnectMsg& msg) {
      ENVOY_LOG(trace, "ssh fake upstream: received DisconnectMsg");
      auto desc = *msg.description;
      if (opts_->on_disconnect) {
        ENVOY_LOG(trace, "ssh fake upstream: invoking on_disconnect callback");
        opts_->on_disconnect(msg);
      }
      return absl::CancelledError(fmt::format("received disconnect: {}{}{}",
                                              openssh::disconnectCodeToString(*msg.reason_code),
                                              desc.empty() ? "" : ": ", desc));
    },
    [&](wire::ServiceRequestMsg& msg) {
      ENVOY_LOG(trace, "ssh fake upstream: received ServiceRequestMsg");
      ASSERT(msg.service_name == "ssh-userauth");
      user_auth_service_->registerMessageHandlers(*msg_dispatcher_);
      msg_dispatcher_->unregisterHandler(wire::SshMessageType::ServiceRequest);
      return sendMessageToConnection(wire::ServiceAcceptMsg{.service_name = msg.service_name}).status();
    },
    [&](auto&) {
      return absl::InvalidArgumentError(fmt::format("received unexpected message type: {}", msg.msg_type()));
    });
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec