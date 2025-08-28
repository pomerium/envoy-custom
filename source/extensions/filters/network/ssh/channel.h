#pragma once

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/passthrough_state.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "source/common/http/utility.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
class ChannelCallbacks {
public:
  virtual ~ChannelCallbacks() = default;
  virtual absl::Status sendMessageToConnection(wire::Message&& msg) PURE;
  virtual uint32_t channelId() const PURE;

  // Closes the channel. If a non-ok error is passed, the underlying connection will be terminated.
  virtual void closeChannel(absl::Status err = absl::OkStatus()) PURE;
};

class Channel {
public:
  virtual ~Channel() = default;
  virtual void setChannelCallbacks(ChannelCallbacks& callbacks) {
    callbacks_ = &callbacks;
  }
  virtual absl::Status open() {
    wire::ChannelOpenMsg open;
    open.channel_type = channelType();
    open.sender_channel = callbacks_->channelId();
    open.initial_window_size = 2097152; // TODO
    open.max_packet_size = 32768;
    open.extra = extra();
    return callbacks_->sendMessageToConnection(std::move(open));
  }
  virtual std::string channelType() PURE;
  virtual bytes extra() { return {}; }

  virtual absl::Status writeMessage(wire::Message&& msg) {
    return callbacks_->sendMessageToConnection(std::move(msg));
  }
  virtual absl::Status readMessage(const wire::Message& msg) PURE;

  virtual absl::Status onChannelOpened() PURE;
  virtual absl::Status onChannelOpenFailed(const std::string& description) PURE;

protected:
  ChannelCallbacks* callbacks_;
};

class HandoffChannelCallbacks {
public:
  virtual ~HandoffChannelCallbacks() = default;
  virtual void onHandoffComplete() PURE;
};

class HandoffChannel : public Channel {
public:
  HandoffChannel(const HandoffInfo& info, HandoffChannelCallbacks& callbacks)
      : info_(info),
        handoff_callbacks_(callbacks) {}
  std::string channelType() override {
    return info_.channel_info->channel_type();
  }
  absl::Status onChannelOpened() override {
    if (info_.pty_info == nullptr) {
      return absl::InvalidArgumentError("session is not interactive");
    }
    // channel is open, now request a pty
    wire::ChannelRequestMsg channelReq{
      .want_reply = true,
      .request = wire::PtyReqChannelRequestMsg{
        .term_env = info_.pty_info->term_env(),
        .width_columns = info_.pty_info->width_columns(),
        .height_rows = info_.pty_info->height_rows(),
        .width_px = info_.pty_info->width_px(),
        .height_px = info_.pty_info->height_px(),
        .modes = info_.pty_info->modes(),
      },
    };
    return callbacks_->sendMessageToConnection(std::move(channelReq));
  }
  absl::Status onChannelOpenFailed(const std::string& description) override {
    // this should end the connection
    return absl::InvalidArgumentError(description);
  }
  absl::Status readMessage(const wire::Message& msg) override {
    return msg.visit(
      // 3: PTY open request
      [&](const wire::ChannelSuccessMsg&) {
        // open a shell; this logic is only reached after requesting a pty
        wire::ChannelRequestMsg shellReq;
        shellReq.request = wire::ShellChannelRequestMsg{};
        shellReq.want_reply = false;
        auto r = callbacks_->sendMessageToConnection(std::move(shellReq));
        RELEASE_ASSERT(r.ok(), "failed to send ShellChannelRequestMsg");

        handoff_callbacks_.onHandoffComplete();

        return absl::OkStatus();
      },
      [&](const wire::ChannelFailureMsg&) {
        return absl::InternalError("failed to open upstream tty");
      },
      [](const auto& msg) {
        return absl::InternalError(fmt::format("received unexpected message from upstream during handoff: {}", msg.msg_type()));
      });
  }

private:
  const HandoffInfo& info_;
  HandoffChannelCallbacks& handoff_callbacks_;
};

class ChannelEventCallbacks {
public:
  virtual ~ChannelEventCallbacks() = default;
  virtual void sendChannelEvent(const pomerium::extensions::ssh::ChannelEvent& ev) PURE;
};

class InternalDownstreamChannel : public Channel,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  InternalDownstreamChannel(ChannelEventCallbacks& event_callbacks,
                            Network::IoHandlePtr io_handle,
                            Envoy::Event::Dispatcher& connection_dispatcher,
                            const std::string& channel_type)
      : io_handle_(std::move(io_handle)),
        connection_dispatcher_(connection_dispatcher),
        channel_type_(channel_type),
        event_callbacks_(event_callbacks) {
    loadPassthroughMetadata();
  }

  std::string channelType() override {
    return channel_type_;
  }

  bytes extra() override {
    Buffer::OwnedImpl extra;
    auto addrData = Envoy::Http::Utility::parseAuthority(server_name_);
    wire::write_opt<wire::LengthPrefixed>(extra, std::string(addrData.host_));
    wire::write<uint32_t>(extra, 443);
    wire::write_opt<wire::LengthPrefixed>(extra, downstream_addr_->ip()->addressAsString());
    wire::write<uint32_t>(extra, downstream_addr_->ip()->port());
    return wire::flushTo<bytes>(extra);
  }

  absl::Status onChannelOpened() override {
    connection_dispatcher_.post([this] {
      io_handle_->initializeFileEvent(
        connection_dispatcher_,
        [this](uint32_t events) {
          onFileEvent(events);
          // errors returned from this callback are fatal
          return absl::OkStatus();
        },
        ::Envoy::Event::PlatformDefaultTriggerType,
        ::Envoy::Event::FileReadyType::Read | ::Envoy::Event::FileReadyType::Closed);
    });
    if (downstream_addr_->ip()->port() == 0) {
      // channel->demoSendSocks5Connect();
    }
    pomerium::extensions::ssh::ChannelEvent ev;
    ev.set_channel_id(callbacks_->channelId());
    auto* opened = ev.mutable_internal_channel_opened();
    opened->set_channel_id(callbacks_->channelId());
    opened->set_peer_address(downstream_addr_->asStringView());

    // pomerium::extensions::ssh::StreamEvent stream_ev;
    // *stream_ev.mutable_channel_event() = ev;
    // ClientMessage msg;
    // *msg.mutable_event() = stream_ev;
    event_callbacks_.sendChannelEvent(ev);
    return absl::OkStatus();
  }

  absl::Status onChannelOpenFailed(const std::string& description) override {
    // this is not necessarily an error that should end the connection. we can just close the
    // io handle and send a channel event
    io_handle_->close();
    onIoHandleClosed(description);
    return absl::OkStatus();
  }

  absl::Status readMessage(const wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        Buffer::OwnedImpl buffer(msg.data->data(), msg.data->size());
        auto r = io_handle_->write(buffer);
        if (!r.ok()) {
          ENVOY_LOG(debug, "write: io error: {}", r.err_->getErrorDetails());
          return absl::OkStatus();
        }
        ENVOY_LOG(debug, "wrote {} bytes to socket", r.return_value_);
        return absl::OkStatus();
      },
      [this](const wire::ChannelEOFMsg&) {
        ENVOY_LOG(debug, "got eof message");
        io_handle_->shutdown(SHUT_WR);
        return absl::OkStatus();
      },
      [this](const wire::ChannelCloseMsg&) {
        ENVOY_LOG(debug, "got close message");
        io_handle_->close();
        onIoHandleClosed("channel closed");
        return absl::OkStatus();
      },
      [&](const auto& msg) {
        return absl::InternalError(fmt::format("unexpected message type: {}", msg.msg_type()));
      });
  }

private:
  void onFileEvent(uint32_t events) {
    ASSERT(connection_dispatcher_.isThreadSafe());
    if ((events & Envoy::Event::FileReadyType::Closed) != 0) {
      onIoHandleClosed("connection closed by upstream");
      return;
    }

    absl::Status status;
    if ((events & Envoy::Event::FileReadyType::Read) != 0) {
      status = readReady();
    }

    if (!status.ok()) {
      io_handle_->close();
      onIoHandleClosed(statusToString(status));
    }

    // if ((events & FileReadyType::Write) != 0) {
    //   status = writeReady();
    // }
  }

  void onIoHandleClosed(const std::string& reason) {
    ASSERT(!closed_);
    closed_ = true;

    io_handle_->resetFileEvents();
    pomerium::extensions::ssh::ChannelEvent ev;
    auto* opened = ev.mutable_internal_channel_closed();
    opened->set_channel_id(callbacks_->channelId());
    opened->set_reason(reason);

    // pomerium::extensions::ssh::StreamEvent stream_ev;
    // *stream_ev.mutable_channel_event() = ev;
    // ClientMessage msg;
    // *msg.mutable_event() = stream_ev;
    event_callbacks_.sendChannelEvent(ev);
    //   ASSERT(transport_dispatcher_->isThreadSafe());
    //   auto r = io_handle_->close();
    //   if (!r.ok()) {
    //     return absl::CancelledError(fmt::format("close: io error: {}", r.err_->getErrorDetails()));
    //   }
    // ENVOY_LOG(info, "socket closed", r.return_value_);
  }

  absl::Status readReady() {
    ASSERT(connection_dispatcher_.isThreadSafe());
    // Read from the transport socket and encapsulate the data into a ChannelData message, then
    // write it on the channel
    Buffer::OwnedImpl buffer;
    auto r = io_handle_->read(buffer, std::nullopt);
    if (!r.ok()) {
      return absl::CancelledError(fmt::format("read: io error: {}", r.err_->getErrorDetails()));
    }
    wire::ChannelDataMsg dataMsg;
    dataMsg.data = wire::flushTo<bytes>(buffer);
    return callbacks_->sendMessageToConnection(wire::Message{std::move(dataMsg)});
  }

  void loadPassthroughMetadata() {
    auto passthroughState = Network::InternalStreamPassthroughState::fromIoHandle(*io_handle_);

    envoy::config::core::v3::Metadata passthrough_metadata;
    StreamInfo::FilterStateImpl passthrough_filter_state{StreamInfo::FilterState::LifeSpan::Connection};

    passthroughState->mergeInto(passthrough_metadata, passthrough_filter_state);

    auto* serverName = passthrough_filter_state.getDataReadOnly<RequestedServerName>(RequestedServerName::key());
    ASSERT(serverName != nullptr);
    server_name_ = serverName->value();

    auto* addr = passthrough_filter_state.getDataReadOnly<Network::AddressObject>(DownstreamSourceAddressFilterStateFactory::key());
    ASSERT(addr != nullptr);
    downstream_addr_ = addr->address();
  }

  bool closed_{false}; // for debug purposes only
  Network::IoHandlePtr io_handle_;
  Envoy::Event::Dispatcher& connection_dispatcher_;
  std::string channel_type_;

  std::string server_name_;
  Envoy::Network::Address::InstanceConstSharedPtr downstream_addr_;
  ChannelEventCallbacks& event_callbacks_;
};

class HijackedChannelCallbacks {
public:
  virtual ~HijackedChannelCallbacks() = default;
  virtual void initHandoff(pomerium::extensions::ssh::SSHChannelControlAction_HandOffUpstream*) PURE;
};

class HijackedChannel : public Channel, public ChannelStreamCallbacks, public Logger::Loggable<Logger::Id::filter> {
public:
  HijackedChannel(HijackedChannelCallbacks& hijack_callbacks,
                  std::unique_ptr<ChannelStreamServiceClient> channel_client,
                  const pomerium::extensions::ssh::InternalTarget& config,
                  const wire::ChannelOpenMsg& channel_open)
      : channel_client_(std::move(channel_client)),
        config_(config),
        hijack_callbacks_(hijack_callbacks),
        channel_open_(channel_open) {
    channel_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus code, std::string err) {
      callbacks_->closeChannel(absl::Status(static_cast<absl::StatusCode>(code), err));
    });
  }

  absl::Status open() override {
    pomerium::extensions::ssh::FilterMetadata typed_metadata;
    if (config_.has_set_metadata()) {
      config_.set_metadata().typed_filter_metadata().at("com.pomerium.ssh").UnpackTo(&typed_metadata);
    }
    typed_metadata.set_channel_id(callbacks_->channelId());
    envoy::config::core::v3::Metadata metadata;
    ProtobufWkt::Any typed_metadata_any;
    typed_metadata_any.PackFrom(typed_metadata);
    metadata.mutable_typed_filter_metadata()->insert({"com.pomerium.ssh"s, std::move(typed_metadata_any)});
    stream_ = channel_client_->start(this, metadata);
    return readMessage(wire::Message{channel_open_});
  }

  absl::Status onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& msg) override {
    switch (msg->message_case()) {
    case pomerium::extensions::ssh::ChannelMessage::kRawBytes: {
      wire::Message anyMsg{};
      auto stat = with_buffer_view(msg->raw_bytes().value(), [&anyMsg](Envoy::Buffer::Instance& buffer) {
        return anyMsg.decode(buffer, buffer.length());
      });
      if (!stat.ok()) {
        return statusf("received invalid channel message: {}", stat.status());
      }
      ENVOY_LOG(debug, "sending channel message to downstream: {}", anyMsg.msg_type());
      return callbacks_->sendMessageToConnection(std::move(anyMsg));
    }
    case pomerium::extensions::ssh::ChannelMessage::kChannelControl: {
      pomerium::extensions::ssh::SSHChannelControlAction ctrl_action;
      msg->channel_control().control_action().UnpackTo(&ctrl_action);
      switch (ctrl_action.action_case()) {
      case pomerium::extensions::ssh::SSHChannelControlAction::kHandOff: {
        // allow the client to be closed without ending the connection
        channel_client_->setOnRemoteCloseCallback(nullptr);
        stream_->resetStream();
        auto* handOffMsg = ctrl_action.mutable_hand_off();
        hijack_callbacks_.initHandoff(handOffMsg);
        return absl::OkStatus();
      }
      default:
        return absl::InternalError(fmt::format("received invalid channel message: unknown action type: {}",
                                               static_cast<int>(ctrl_action.action_case())));
      }
    }
    default:
      return absl::InternalError(fmt::format("received invalid channel message: unknown message type: {}",
                                             static_cast<int>(msg->message_case())));
    }
  }

  std::string channelType() override { return ""; }

  absl::Status readMessage(const wire::Message& msg) override {
    ChannelMessage channel_msg;
    google::protobuf::BytesValue b;
    auto msgData = encodeTo<std::string>(msg);
    if (!msgData.ok()) {
      return absl::InvalidArgumentError(fmt::format("received invalid message: {}", msgData.status()));
    }
    *b.mutable_value() = *msgData;
    *channel_msg.mutable_raw_bytes() = b;
    stream_->sendMessage(channel_msg, false);
    return absl::OkStatus();
  }

  absl::Status onChannelOpened() override {
    return absl::OkStatus();
  }

  absl::Status onChannelOpenFailed(const std::string& description) override {
    // this should end the connection
    return absl::InvalidArgumentError(description);
  }

private:
  std::unique_ptr<ChannelStreamServiceClient> channel_client_;
  pomerium::extensions::ssh::InternalTarget config_;
  Grpc::AsyncStream<ChannelMessage> stream_;
  HijackedChannelCallbacks& hijack_callbacks_;
  wire::ChannelOpenMsg channel_open_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec