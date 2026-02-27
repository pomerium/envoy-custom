#include "test/extensions/filters/network/ssh/ssh_upstream.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshFakeUpstreamHandler::SshFakeUpstreamHandler(Server::Configuration::ServerFactoryContext& context,
                                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                               std::shared_ptr<SshFakeUpstreamHandlerOpts> opts)
    : TransportBase<SshFakeUpstreamHandlerCodec>(context, config, *this),
      opts_(opts) {}

SshFakeUpstreamHandler::CodecCallbacks::CodecCallbacks(Network::Connection& connection)
    : connection_(connection) {}

void SshFakeUpstreamHandler::CodecCallbacks::onDecodingFailure(absl::string_view reason) {
  connection_.close(Network::ConnectionCloseType::NoFlush, reason);
}

void SshFakeUpstreamHandler::CodecCallbacks::writeToConnection(Buffer::Instance& buffer) {
  connection_.write(buffer, false);
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
    : ConnectionService(parent, Peer::Downstream),
      parent_(parent) {
  (void)parent_;
}

absl::Status SshFakeUpstreamHandler::FakeUpstreamConnectionService::handleMessage(wire::Message&& msg) {
  return std::move(msg).visit(
    [&](wire::ChannelOpenMsg&& msg) {
      if (!parent_.opts_->on_channel_open_request) {
        PANIC("test bug: on_channel_open_request callback unset but required");
      }
      auto id = transport_.channelIdManager().allocateNewChannel(local_peer_);
      RETURN_IF_NOT_OK(id.status());
      auto stat = transport_.channelIdManager().bindChannelID(*id, PeerLocalID{
                                                                     .channel_id = msg.sender_channel,
                                                                     .local_peer = local_peer_,
                                                                   },
                                                              false);
      ASSERT(stat.ok());
      auto ch = std::make_unique<FakeUpstreamChannel>(parent_.opts_->on_channel_open_request(msg));
      RETURN_IF_NOT_OK(startChannel(std::move(ch), *id).status());
      return absl::OkStatus();
    },
    [&](wire::ChannelOpenConfirmationMsg&& msg) {
      auto id = msg.recipient_channel;
      auto stat = transport_.channelIdManager().bindChannelID(id,
                                                              PeerLocalID{
                                                                .channel_id = msg.sender_channel,
                                                                .local_peer = local_peer_,
                                                              },
                                                              false);
      if (!parent_.opts_->on_channel_accepted) {
        PANIC("test bug: on_channel_accepted callback unset but required");
      }
      auto ch = std::make_unique<FakeUpstreamChannel>(parent_.opts_->on_channel_accepted(msg));
      RETURN_IF_NOT_OK(startChannel(std::move(ch), id).status());
      msg.sender_channel = msg.recipient_channel;
      return channels_[id]->readMessage(std::move(msg));
    },
    [&](wire::ChannelOpenFailureMsg&& msg) {
      auto id = msg.recipient_channel;
      if (!parent_.opts_->on_channel_rejected) {
        PANIC("test bug: on_channel_rejected callback unset but required");
      }
      auto ch = std::make_unique<FakeUpstreamChannel>(parent_.opts_->on_channel_rejected(msg));
      RETURN_IF_NOT_OK(startChannel(std::move(ch), id).status());
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
      auto desc = *msg.description;
      return absl::CancelledError(fmt::format("received disconnect: {}{}{}",
                                              openssh::disconnectCodeToString(*msg.reason_code),
                                              desc.empty() ? "" : ": ", desc));
    },
    [&](wire::ServiceRequestMsg& msg) {
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