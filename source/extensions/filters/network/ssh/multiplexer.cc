#include "source/extensions/filters/network/ssh/multiplexer.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SessionMultiplexer::SessionMultiplexer(
  Api::Api& api,
  std::shared_ptr<ThreadLocal::TypedSlot<SharedThreadLocalData>> tls,
  Dispatcher& dispatcher)
    : api_(api),
      tls_(tls),
      local_dispatcher_(dispatcher) {
  (void)api_;
}

void SessionMultiplexer::onStreamBegin(const AuthState& auth_state) {
  info_ = auth_state.multiplexing_info;
  switch (info_.mode) {
  case Codec::MultiplexingMode::Source: {
    current_stream_id_ = auth_state.stream_id;

    ENVOY_LOG(debug, "new multiplex source: {}", auth_state.stream_id);
    (*tls_)->beginSession(auth_state.stream_id, shared_from_this(), &local_dispatcher_);
    break;
  }
  case Codec::MultiplexingMode::Mirror: {
    ENVOY_LOG(debug, "new multiplex mirror: {}", info_.source_stream_id);
    // NB: session is attached later, after channel is opened
    current_stream_id_ = auth_state.multiplexing_info.source_stream_id;
    break;
  }
  default:
    PANIC("unreachable");
  }
}

void SessionMultiplexer::onStreamEnd() {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  if (!stream_ending_ && current_stream_id_.has_value()) {
    stream_ending_ = true;
    (*tls_)->shutdownSession(current_stream_id_.value());
  }
}

void SessionMultiplexer::onEnd() {
  ASSERT(info_.mode == Codec::MultiplexingMode::Mirror);
  if (!stream_ending_ && current_stream_id_.has_value()) {
    stream_ending_ = true;
    (*tls_)->detachFromSession(*current_stream_id_, shared_from_this());
    current_stream_id_.reset();
    source_interface_.reset();
    wire::DisconnectMsg dc;
    dc.reason_code = SSH2_DISCONNECT_BY_APPLICATION;
    dc.description = "session ended";
    auto _ = info_.transport_callbacks->sendMessageToConnection(dc); // todo: handle error
  }
}

void SessionMultiplexer::handleDownstreamToUpstreamMessage(wire::Message& msg) {
  if (info_.mode != Codec::MultiplexingMode::Mirror || stream_ending_) {
    return;
  }
  msg.visit(
    [&](const wire::ChannelOpenMsg& msg) {
      sender_channel_ = msg.sender_channel;
      wire::ChannelOpenConfirmationMsg confirm;
      confirm.sender_channel = 1;
      confirm.recipient_channel = *sender_channel_;
      confirm.initial_window_size = msg.initial_window_size;
      confirm.max_packet_size = msg.max_packet_size;
      auto _ = info_.transport_callbacks->sendMessageToConnection(confirm); // todo: handle error
    },
    [&](const wire::ChannelRequestMsg& channel_req) {
      if (!sender_channel_.has_value()) {
        return;
      }
      channel_req.msg.visit(
        [&](const wire::PtyReqChannelRequestMsg&) {
          wire::ChannelSuccessMsg success;
          success.recipient_channel = *sender_channel_;
          auto _ = info_.transport_callbacks->sendMessageToConnection(success); // todo: handle error
        },
        [&](const wire::ShellChannelRequestMsg&) {
          ENVOY_LOG(debug, "attaching mirror to session: {}", info_.source_stream_id);
          wire::ChannelSuccessMsg success;
          success.recipient_channel = *sender_channel_;
          auto _ = info_.transport_callbacks->sendMessageToConnection(success); // todo: handle error

          source_interface_ = (*tls_)->attachToSession(*info_.source_stream_id, shared_from_this(), &local_dispatcher_);
        },
        [&](const wire::WindowDimensionChangeChannelRequestMsg&) {
          resizeSource(channel_req);
        },
        [](const auto&) {});
    },
    [&](const wire::ChannelDataMsg& msg) {
      if (source_interface_) {
        source_interface_->inject(msg);
      }
    },
    [](const auto&) {});
}

void SessionMultiplexer::handleUpstreamToDownstreamMessage(wire::Message& msg) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  msg.visit(
    [&](const wire::ChannelDataMsg& msg) {
      updateSource(msg);
    },
    [](const auto&) {});
}

void SessionMultiplexer::onMsg(const wire::Message& msg) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Mirror);

  (void)info_.transport_callbacks->sendMessageToConnection(msg);
}

void SessionMultiplexer::inject(const wire::ChannelDataMsg& msg) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  info_.transport_callbacks->forward(
    std::make_unique<SSHRequestCommonFrame>(*current_stream_id_, std::make_unique<wire::Message>(msg)));
}

void SessionMultiplexer::onMirrorAdded(std::shared_ptr<MirrorCallbacks> mc) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  active_mirrors_.insert(mc);
  // replay the log
  // demo code only!!! this is terrible
  for (const auto& msg : log_) {
    mc->onMsg(msg);
  }
}

void SessionMultiplexer::onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  active_mirrors_.erase(mc);

  if (stream_ending_ && active_mirrors_.empty()) {
    (*tls_)->endSession(*current_stream_id_);
    current_stream_id_.reset();
  }
}

void SessionMultiplexer::updateSource(const wire::ChannelDataMsg& msg) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  log_.emplace_back(msg);
  for (const auto& mirror : active_mirrors_) {
    mirror->onMsg(log_.back());
  }
}

void SessionMultiplexer::resizeSource(const wire::ChannelRequestMsg& msg) {
  ASSERT(info_.mode == Codec::MultiplexingMode::Source);

  log_.emplace_back(msg);
  for (const auto& mirror : active_mirrors_) {
    mirror->onMsg(log_.back());
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec