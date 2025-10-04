#include "source/extensions/filters/network/ssh/reverse_tunnel.h"
#include "source/common/status.h"
#include "source/common/math.h"
#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/socks5.h"
#include "source/extensions/filters/network/ssh/stream_address.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.validate.h"
#include "source/extensions/io_socket/user_space/io_handle_impl.h"
#include "source/common/network/connection_impl.h"
#include "envoy/network/client_connection_factory.h"
#include "source/common/grpc/common.h"
#include "source/common/stream_info/filter_state_impl.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#include "readerwriterqueue/readerwriterqueue.h"
#pragma clang diagnostic pop
#pragma clang unsafe_buffer_usage end

namespace Envoy::Network {

class InternalStreamPassthroughState : public Envoy::Extensions::IoSocket::UserSpace::PassthroughStateImpl {
public:
  using enum PassthroughStateImpl::State;

  void initialize(std::unique_ptr<envoy::config::core::v3::Metadata> metadata,
                  const StreamInfo::FilterState::Objects& filter_state_objects) override {
    ASSERT(state_ == State::Created);
    PassthroughStateImpl::initialize(std::move(metadata), filter_state_objects);
    ASSERT(state_ == State::Initialized);
    if (init_callback_ == nullptr) {
      return;
    }
    std::exchange(init_callback_, nullptr)();
  }

  void setOnInitializedCallback(absl::AnyInvocable<void()> callback) {
    ASSERT(init_callback_ == nullptr && state_ < State::Done);
    if (state_ == State::Created) {
      init_callback_ = std::move(callback);
      return;
    }
    callback();
  }

  bool isInitialized() const {
    return state_ == State::Initialized;
  }

  static std::shared_ptr<InternalStreamPassthroughState> fromIoHandle(IoHandle& io_handle) {
    return std::dynamic_pointer_cast<InternalStreamPassthroughState>(
      dynamic_cast<Extensions::IoSocket::UserSpace::IoHandleImpl&>(io_handle).passthroughState());
  }

private:
  absl::AnyInvocable<void()> init_callback_;
};

} // namespace Envoy::Network

using Envoy::Extensions::IoSocket::UserSpace::IoHandleFactory;

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

constexpr uint32_t MaxPacketSize = IoSocket::UserSpace::FRAGMENT_SIZE * IoSocket::UserSpace::MAX_FRAGMENT;

using MessageQueue = moodycamel::ReaderWriterQueue<std::unique_ptr<wire::Message>>;

class RemoteStreamHandlerCallbacks {
public:
  virtual ~RemoteStreamHandlerCallbacks() = default;
  virtual void scheduleQueueCallback() PURE;
  virtual void scheduleErrorCallback(absl::Status error, bool send_eof) PURE;
  virtual void addDiagnostic(std::unique_ptr<pomerium::extensions::ssh::Diagnostic> diagnostic) PURE;
};

class RemoteStreamHandler : public Logger::Loggable<Logger::Id::filter>,
                            public Event::DispatcherThreadDeletable,
                            public Socks5ChannelCallbacks {
public:
  RemoteStreamHandler(RemoteStreamHandlerCallbacks& callbacks,
                      Envoy::Event::Dispatcher& remote_dispatcher,
                      IoSocket::UserSpace::IoHandleImplPtr r_io_handle,
                      Network::Address::SshEndpointMetadataConstSharedPtr metadata,
                      std::shared_ptr<const envoy::config::core::v3::Address> upstream_address,
                      const wire::ChannelOpenConfirmationMsg& confirm,
                      MessageQueue** local_queue)
      : max_packet_size_(confirm.max_packet_size),
        channel_id_(confirm.recipient_channel),
        upstream_window_(confirm.initial_window_size),
        io_handle_(std::move(r_io_handle)),
        remote_dispatcher_(remote_dispatcher),
        callbacks_(callbacks),
        upstream_address_(upstream_address),
        metadata_(metadata) {
    ASSERT(upstream_address_ != nullptr);
    ASSERT(metadata_ != nullptr);
    *local_queue = &local_queue_;
    auto start = absl::Now();
    bool isDynamic = metadata_->server_port().is_dynamic();
    ENVOY_LOG(debug, "channel {}: waiting to initialize", channel_id_);
    remote_dispatcher_.post([this, isDynamic, start] {
      ENVOY_LOG(debug, "channel {}: initializing (delay: {})", channel_id_, absl::FormatDuration(absl::Now() - start));
      remote_queue_callback_ = remote_dispatcher_.createSchedulableCallback([this] {
        onRemoteQueueReadyRead();
      });
      // Set the downstream buffer high watermark to match the local window size. This allows us to
      // apply backpressure to the upstream ssh channel if the downstream is not reading from the
      // write buffer.
      // Note that the local socket starts with watermarks disabled. They are turned on/off based on
      // ssh protocol flow control events.
      io_handle_->getWriteBuffer()->setWatermarks(local_window_);

      if (isDynamic) {
        ENVOY_LOG(debug, "channel {}: starting socks5 handshake", channel_id_);
        startSocks5Handshake();
        initializeIoHandleEvents(Event::FileReadyType::Closed);
      } else {
        initializeIoHandleEvents(Event::FileReadyType::Read | Event::FileReadyType::Write | Event::FileReadyType::Closed);
      }
    });
  }

  ~RemoteStreamHandler() {
    ENVOY_LOG(debug, "channel {}: destroying remote stream handler", channel_id_);
    maybeCloseIoHandle();
  }

  static void detach(std::unique_ptr<RemoteStreamHandler> self) {
    self->detach_lock_.Lock();
    self->detached_ = true;
    self->detach_lock_.Unlock();
    self->remote_dispatcher_.deleteInDispatcherThread(std::move(self));
  }

  void enqueueMessage(std::unique_ptr<wire::Message> msg) {
    bool ok = remote_queue_.enqueue(std::move(msg));
    ASSERT(ok);
    remote_queue_callback_->scheduleCallbackNextIteration();
  }

private:
  void onError(absl::Status err) {
    ENVOY_LOG(debug, "channel {}: remote error: {}", channel_id_, err);
    maybeCloseIoHandle();

    bool sendEof = false;
    if (socks5_handshaker_.has_value()) {
      // If an error occured in the middle of the socks5 handshake, we have to send an EOF message
      // to the client.
      sendEof = true;
    }

    closing_ = true;
    detach_lock_.Lock();
    if (!detached_) {
      ENVOY_LOG(debug, "channel {}: scheduling error callback", channel_id_);
      callbacks_.scheduleErrorCallback(err, sendEof);
    } else {
      ENVOY_LOG(debug, "channel {}: not scheduling error callback (detached)", channel_id_);
    }
    detach_lock_.Unlock();
  }

  void initializeIoHandleEvents(uint32_t events) {
    io_handle_->initializeFileEvent(
      remote_dispatcher_,
      [this](uint32_t events) {
        onFileEvent(events);
        // errors returned from this callback are fatal
        return absl::OkStatus();
      },
      Event::PlatformDefaultTriggerType,
      events);
  }

  void onFileEvent(uint32_t events) {
    ASSERT(remote_dispatcher_.isThreadSafe());
    if ((events & Envoy::Event::FileReadyType::Closed) != 0) {
      onError(absl::CancelledError("closed by upstream"));
      return;
    }

    absl::Status status;
    if ((events & Envoy::Event::FileReadyType::Read) != 0) {
      status = readReady();
    } else if ((events & Envoy::Event::FileReadyType::Write) != 0) {
      // write buffer low watermark event
      status = writeReady();
    }

    if (!status.ok()) {
      onError(status);
    }
  }

  void onRemoteQueueReadyRead() {
    std::unique_ptr<wire::Message> msgPtr;
    while (remote_queue_.try_dequeue(msgPtr)) {
      wire::Message& msg = *msgPtr;
      msg.visit(
        [&](wire::ChannelDataMsg& msg) {
          // subtract from the local window
          if (sub_overflow(&local_window_, static_cast<uint32_t>(msg.data->size()))) {
            // the upstream wrote more bytes than allowed by the local window
            ENVOY_LOG(debug, "channel {}: flow control: remote exceeded local window", channel_id_);
            onError(absl::InvalidArgumentError(fmt::format("channel {}: local window exceeded", channel_id_)));
            return;
          }
          // process the channel data message
          if (auto stat = readChannelData(msg); !stat.ok()) {
            onError(stat);
            return;
          }
          // check if we need to increase the local window
          if (local_window_ < wire::ChannelWindowSize / 2) {
            if (!io_handle_->isPeerWritable()) {
              ENVOY_LOG(debug, "channel {}: flow control: not increasing local window size", channel_id_);
              // Only increase the window size for the upstream if the downstream is writable. We
              // can queue at most one full window of data, after which the upstream will stop
              // writing until we increase the window size.
              return;
            }
            local_window_ += wire::ChannelWindowSize;
            ENVOY_LOG(debug, "channel {}: flow control: increasing local window size ({} -> {})",
                      channel_id_, local_window_, local_window_ + wire::ChannelWindowSize);
            num_local_window_adjustments_++;

            enqueueLocalMessage(std::make_unique<wire::Message>(wire::ChannelWindowAdjustMsg{
              .recipient_channel = channel_id_,
              .bytes_to_add = wire::ChannelWindowSize,
            }));
          }
        },
        [&](wire::ChannelWindowAdjustMsg& msg) {
          if (add_overflow(&upstream_window_, *msg.bytes_to_add)) {
            onError(absl::InvalidArgumentError("invalid window adjust"));
            return;
          }
          ENVOY_LOG(debug, "channel {}: flow control: remote window adjusted by {} bytes", channel_id_, *msg.bytes_to_add);
          if (!io_handle_->isWritable()) {
            // disable write watermarks if we previously ran out of window space and the peer's
            // high watermark was triggered
            ENVOY_LOG(debug, "channel {}: flow control: activating low watermark", channel_id_);
            io_handle_->setWatermarks(0);
          }
          return;
        },
        [&](wire::ChannelEOFMsg&) {
          maybeWarnOnEOF();
          // Note: we won't intentionally close the io handle ourselves until this object is about
          // to be destroyed, and all messages have been read from the queue. However, it could
          // still be closed by the peer. shutdown() can only be called if the handle is open.
          if (io_handle_->isOpen()) {
            io_handle_->shutdown(ENVOY_SHUT_WR);
          }
        },
        [&](auto& msg) {
          IS_ENVOY_BUG(fmt::format("channel {}: unexpected message type: {}", channel_id_, msg.msg_type()));
        });
    }
  }

  void maybeCloseIoHandle() {
    ASSERT(remote_dispatcher_.isThreadSafe());
    if (io_handle_->isOpen()) {
      ENVOY_LOG(debug, "channel {}: closing remote io handle", channel_id_);
      io_handle_->close();
    }
  }

  absl::Status readReady() {
    ASSERT(remote_dispatcher_.isThreadSafe());
    if (upstream_window_ == 0) {
      // If we have run out of window space, trigger the buffer's high watermark and return. This
      // will prevent read events until we receive a window adjustment from the upstream.
      ENVOY_LOG(debug, "channel {}: flow control: remote window exhausted; activating high watermark");
      io_handle_->setWatermarks(1); // 1-byte high watermark = any buffered data
      return absl::OkStatus();
    }

    // Read from the transport socket and encapsulate the data into a ChannelData message, then
    // write it on the channel
    // TODO: this is inefficient
    Buffer::OwnedImpl buffer;
    auto r = io_handle_->read(buffer, std::min(max_packet_size_, upstream_window_));
    if (!r.ok()) {
      if (r.wouldBlock()) {
        return absl::OkStatus();
      }
      return absl::CancelledError(fmt::format("read: io error: {}", r.err_->getErrorDetails()));
    }
    ASSERT(r.return_value_ <= upstream_window_); // sanity check
    upstream_window_ -= static_cast<uint32_t>(r.return_value_);

    ENVOY_LOG(debug, "channel {}: wrote {} bytes from upstream", channel_id_, r.return_value_);
    enqueueLocalMessage(std::make_unique<wire::Message>(wire::ChannelDataMsg{
      .recipient_channel = channel_id_,
      .data = wire::flushTo<bytes>(buffer),
    }));

    return absl::OkStatus();
  }

  absl::Status writeReady() {
    ASSERT(remote_dispatcher_.isThreadSafe());
    // Flush data from the window buffer to the downstream until the buffer is empty or the
    // downstream high watermark is reached
    while (window_buffer_.length() > 0) {
      auto r = io_handle_->write(window_buffer_);
      if (!r.ok() && !r.wouldBlock()) {
        if (r.err_->getSystemErrorCode() == SOCKET_ERROR_INVAL) {
          // peer is closed. we could check this ourselves, but the socket write() implementation
          // does it anyway, so it would be redundant.
          ENVOY_LOG(debug, "channel {}: downstream closed early, dropping {} bytes", channel_id_, window_buffer_.length());
          window_buffer_.drain(window_buffer_.length());
          return absl::OkStatus();
        }
        return absl::CancelledError(fmt::format("write: io error: {}", r.err_->getErrorDetails()));
      }
      ENVOY_LOG(debug, "channel {}: read {} bytes from downstream", channel_id_, r.return_value_);
    }
    return absl::OkStatus();
  }

  void startSocks5Handshake() {
    socks5_handshaker_.emplace(*this, upstream_address_);
    socks5_handshaker_->startHandshake();
  }

  void writeChannelData(bytes&& data) override {
    if (closing_) {
      return;
    }
    enqueueLocalMessage(std::make_unique<wire::Message>(wire::ChannelDataMsg{
      .recipient_channel = channel_id_,
      .data = std::move(data),
    }));
  }

  void enqueueLocalMessage(std::unique_ptr<wire::Message> msg) {
    ASSERT(remote_dispatcher_.isThreadSafe());
    bool ok = local_queue_.enqueue(std::move(msg));
    ASSERT(ok);

    detach_lock_.Lock();
    if (!detached_) [[likely]] {
      callbacks_.scheduleQueueCallback();
    }
    detach_lock_.Unlock();
  }

  absl::Status readChannelData(const wire::ChannelDataMsg& msg) {
    window_buffer_.add(msg.data->data(), msg.data->size());

    if (socks5_handshaker_.has_value()) {
      auto stat = socks5_handshaker_->readChannelData(window_buffer_);
      if (!stat.ok()) {
        return statusf("socks5 handshake error: {}", stat);
      }
      if (auto&& result = socks5_handshaker_->result(); result.has_value()) {
        ENVOY_LOG(debug, "channel {}: socks5 handshake completed (server address: {})",
                  channel_id_, result.value()->asString());
        if (io_handle_->isOpen()) {
          io_handle_->enableFileEvents(Event::FileReadyType::Read | Event::FileReadyType::Write | Event::FileReadyType::Closed);
        }
        socks5_handshaker_.reset();
      } else {
        ENVOY_LOG(debug, "channel {}: socks5 handshake not complete", channel_id_);
      }
      // Continue if there is more data to be read past the socks5 handshake
      if (window_buffer_.length() == 0) {
        return absl::OkStatus();
      }
    }

    if (auto stat = writeReady(); !stat.ok()) {
      return stat;
    }
    return absl::OkStatus();
  }

  void maybeWarnOnEOF() {
    // If this is the first message received by the server, and we did not send a socks5
    // handshake, it is possible that the server was expecting us to. If the upstream server
    // simply failed to connect, we would have received a channel open failure instead.
    const auto& requestedHost = metadata_->matched_permission().requested_host();
    bool isFirstMsgReceived = local_window_ == wire::ChannelWindowSize &&
                              num_local_window_adjustments_ == 0;
    bool requestedHostHasWildcards = (requestedHost == "" || requestedHost == "localhost" ||
                                      requestedHost.contains("*") || requestedHost.contains("?"));
    if (isFirstMsgReceived && metadata_->server_port().is_dynamic() && requestedHostHasWildcards) {
      auto diag = std::make_unique<pomerium::extensions::ssh::Diagnostic>();
      diag->set_severity(pomerium::extensions::ssh::Diagnostic::Warning);
      diag->set_message("ssh client may be expecting dynamic port-forwarding");

      auto requestedPort = metadata_->matched_permission().requested_port();
      const auto& upstreamAddr = upstream_address_->socket_address().address();
      auto upstreamPort = upstream_address_->socket_address().port_value();
      if (requestedHost == "localhost") {
        // The -R syntax that sends 'localhost' is slightly different
        diag->add_hints(fmt::format("try requesting port 0 instead of {} (ex: '-R :0')", requestedPort));
        diag->add_hints(fmt::format("or, specify a local host:port (ex: '-R {}:{}:{}')",
                                    metadata_->server_port().value(),
                                    upstreamAddr, upstreamPort));
      } else {
        diag->add_hints(fmt::format("try requesting port 0 instead of {} (ex: '-R {}:0')",
                                    requestedPort, requestedHost));
        diag->add_hints(fmt::format("or, specify a local host:port (ex: '-R {}:{}:{}:{}')",
                                    requestedHost,
                                    metadata_->server_port().value(),
                                    upstreamAddr, upstreamPort));
      }
      callbacks_.addDiagnostic(std::move(diag));
    }
  }

  bool closing_{false};
  const uint32_t max_packet_size_{};
  const uint32_t channel_id_{};
  uint32_t local_window_{wire::ChannelWindowSize};
  uint32_t upstream_window_{};
  IoSocket::UserSpace::IoHandleImplPtr io_handle_;
  Envoy::Event::Dispatcher& remote_dispatcher_;
  MessageQueue remote_queue_;
  MessageQueue local_queue_;
  Event::SchedulableCallbackPtr remote_queue_callback_;
  RemoteStreamHandlerCallbacks& callbacks_;
  std::optional<Socks5ClientHandshaker> socks5_handshaker_;
  std::shared_ptr<const envoy::config::core::v3::Address> upstream_address_;
  Buffer::OwnedImpl window_buffer_;
  Network::Address::SshEndpointMetadataConstSharedPtr metadata_;
  uint64_t num_local_window_adjustments_{};

  absl::Mutex detach_lock_;
  bool detached_ ABSL_GUARDED_BY(detach_lock_) = false;
};

class InternalDownstreamChannel final : public Channel,
                                        public RemoteStreamHandlerCallbacks,
                                        public Logger::Loggable<Logger::Id::filter> {
public:
  InternalDownstreamChannel(Network::IoHandlePtr io_handle,
                            Network::Address::SshEndpointMetadataConstSharedPtr metadata,
                            std::shared_ptr<const envoy::config::core::v3::Address> upstream_address,
                            ChannelEventCallbacks& event_callbacks,
                            Envoy::Event::Dispatcher& local_dispatcher,
                            Envoy::Event::Dispatcher& remote_dispatcher)
      : metadata_(metadata),
        local_dispatcher_(local_dispatcher),
        remote_dispatcher_(remote_dispatcher),
        r_io_handle_(&dynamic_cast<IoSocket::UserSpace::IoHandleImpl&>(*io_handle.release())),
        upstream_address_(upstream_address),
        event_callbacks_(event_callbacks),
        local_queue_callback_(local_dispatcher_.createSchedulableCallback([this] {
          onLocalQueueReadyRead();
        })),
        error_callback_(local_dispatcher_.createSchedulableCallback([this] {
          onErrorCallback();
        })),
        stats_timer_(local_dispatcher.createTimer([this] {
          onStatsTimerFired();
        })) {
    loadPassthroughMetadata();
  }

  ~InternalDownstreamChannel() {
    ASSERT(local_dispatcher_.isThreadSafe());
    if (remote_ != nullptr) { // XXX: test this branch
      ENVOY_LOG(debug, "channel {}: detaching", channel_id_);
      RemoteStreamHandler::detach(std::move(remote_));
    }
    stats_timer_->disableTimer();
    local_queue_callback_->cancel();
    error_callback_->cancel();
  }

  // Local thread
  absl::Status setChannelCallbacks(ChannelCallbacks& callbacks) override {
    auto stat = Channel::setChannelCallbacks(callbacks);
    ASSERT(stat.ok()); // default implementation always succeeds

    channel_id_ = callbacks_->channelId();

    // Build and send the ChannelOpen message to the downstream.
    // Normally channels don't send their own ChannelOpen messages, but this is somewhat of a
    // special case, because the channel is owned internally.

    wire::ForwardedTcpipChannelOpenMsg req;
    if (metadata_->matched_permission().requested_host().empty()) {
      // wildcard mode
      req.address_connected = "";
    } else {
      // use the original pattern as the address
      req.address_connected = metadata_->matched_permission().requested_host();
    }
    req.port_connected = metadata_->server_port().value();
    req.originator_address = downstream_address_->ip()->addressAsString(),
    req.originator_port = downstream_address_->ip()->port();

    wire::ChannelOpenMsg open{
      .sender_channel = channel_id_,
      .initial_window_size = wire::ChannelWindowSize,
      .max_packet_size = MaxPacketSize,
      .request = std::move(req),
    };
    ENVOY_LOG(debug, "channel {}: flow control: local window initialized to {}", channel_id_, wire::ChannelWindowSize);

    callbacks.sendMessageLocal(std::move(open));
    return absl::OkStatus();
  }

  // RemoteStreamHandlerCallbacks
  void scheduleQueueCallback() final {
    ASSERT(remote_dispatcher_.isThreadSafe());
    local_queue_callback_->scheduleCallbackNextIteration();
  }

  // RemoteStreamHandlerCallbacks
  void scheduleErrorCallback(absl::Status error, bool send_eof) final {
    ASSERT(remote_dispatcher_.isThreadSafe());
    error_ = error;
    send_eof_ = send_eof;
    error_callback_->scheduleCallbackNextIteration();
  }

  // RemoteStreamHandlerCallbacks
  void addDiagnostic(std::unique_ptr<pomerium::extensions::ssh::Diagnostic> diagnostic) final {
    diagnostics_mu_.Lock();
    diagnostics_.push_back(std::move(diagnostic));
    diagnostics_mu_.Unlock();
  }

  // Local thread
  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&& confirm) override {
    // Note that createSchedulableCallback accepts a std::function, which must be copyable
    ENVOY_LOG(debug, "channel {}: starting remote stream handler", channel_id_);
    remote_ = std::make_unique<RemoteStreamHandler>(*this,
                                                    remote_dispatcher_,
                                                    std::move(r_io_handle_),
                                                    metadata_,
                                                    upstream_address_,
                                                    confirm,
                                                    &local_queue_);
    start_time_ = absl::Now();
    pomerium::extensions::ssh::ChannelEvent ev;
    auto* opened = ev.mutable_internal_channel_opened();
    opened->set_channel_id(channel_id_);
    opened->set_hostname(server_name_); // TODO: it would be better to pass cluster id here instead
    opened->set_path(path_);
    opened->set_peer_address(downstream_address_->asStringView());
    event_callbacks_.sendChannelEvent(ev);
    stats_timer_->enableTimer(std::chrono::seconds(5));
    return absl::OkStatus();
  }

  // Local thread
  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&&) override {
    // this is not necessarily an error that should end the connection. we can just close the
    // io handle and send a channel event
    r_io_handle_->close();

    return absl::OkStatus();
  }

  // Local thread
  absl::Status readMessage(wire::Message&& msg) override {
    msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        tx_bytes_total_ += msg.data->size();
        tx_packets_total_++;
        remote_->enqueueMessage(std::make_unique<wire::Message>(std::move(msg)));
      },
      [&](const wire::ChannelCloseMsg&) {
        ENVOY_LOG(debug, "channel {}: downstream closed", channel_id_);
        maybeSendChannelClose(absl::OkStatus());
      },
      [&](const auto&) {
        remote_->enqueueMessage(std::make_unique<wire::Message>(std::move(msg)));
      });
    return absl::OkStatus();
  }

private:
  std::unique_ptr<RemoteStreamHandler> remote_;

  void loadPassthroughMetadata() {
    auto passthroughState = Network::InternalStreamPassthroughState::fromIoHandle(*r_io_handle_);
    ASSERT(passthroughState->isInitialized());

    envoy::config::core::v3::Metadata passthrough_metadata;
    StreamInfo::FilterStateImpl passthrough_filter_state{StreamInfo::FilterState::LifeSpan::Connection};

    passthroughState->mergeInto(passthrough_metadata, passthrough_filter_state);

    auto* serverName = passthrough_filter_state.getDataReadOnly<RequestedServerName>(RequestedServerName::key());
    ASSERT(serverName != nullptr);
    server_name_ = serverName->value();

    auto* path = passthrough_filter_state.getDataReadOnly<RequestedPath>(RequestedPath::key());
    if (path != nullptr) {
      path_ = path->value();
    }

    auto* addr = passthrough_filter_state.getDataReadOnly<Network::AddressObject>(DownstreamSourceAddressFilterStateFactory::key());
    ASSERT(addr != nullptr);
    downstream_address_ = addr->address();
  }

  void onErrorCallback() {
    ASSERT(local_dispatcher_.isThreadSafe());
    ENVOY_LOG(debug, "channel {}: error: {}", channel_id_, error_);
    stats_timer_->disableTimer();
    // Flush any queued channel messages before sending the channel close message. This is invoked
    // from a separate callback, so it can race if both are scheduled on the current iteration.
    onLocalQueueReadyRead();
    local_queue_callback_->cancel();
    ENVOY_LOG(debug, "channel {}: flushed read queue", channel_id_);
    maybeSendChannelClose(error_);
  }

  void maybeSendChannelClose(absl::Status status) {
    if (channel_close_sent_) {
      ENVOY_LOG(debug, "channel {}: channel close already sent");
      return;
    }
    channel_close_sent_ = true;

    if (send_eof_) {
      ENVOY_LOG(debug, "channel {}: sending eof", channel_id_);
      callbacks_->sendMessageLocal(wire::ChannelEOFMsg{
        .recipient_channel = channel_id_,
      });
    }
    ENVOY_LOG(debug, "channel {}: sending close", channel_id_);
    callbacks_->sendMessageLocal(wire::ChannelCloseMsg{
      .recipient_channel = channel_id_,
    });
    sendChannelCloseEvent(status);
  }

  void sendChannelCloseEvent(absl::Status status) {
    pomerium::extensions::ssh::ChannelEvent ev;
    auto* closed = ev.mutable_internal_channel_closed();
    closed->set_channel_id(channel_id_);
    if (!status.ok()) {
      closed->set_reason(statusToString(status));
    }
    populateChannelStats(closed->mutable_stats());
    diagnostics_mu_.Lock();
    for (auto& diag : diagnostics_) {
      closed->mutable_diagnostics()->AddAllocated(diag.release());
    }
    diagnostics_.clear();
    diagnostics_mu_.Unlock();
    event_callbacks_.sendChannelEvent(std::move(ev));
  }

  void populateChannelStats(pomerium::extensions::ssh::ChannelStats* stats) {
    stats->set_rx_bytes_total(rx_bytes_total_);
    stats->set_tx_bytes_total(tx_bytes_total_);
    stats->set_rx_packets_total(rx_packets_total_);
    stats->set_tx_packets_total(tx_packets_total_);
    *stats->mutable_channel_duration() = Protobuf::util::TimeUtil::NanosecondsToDuration(absl::ToInt64Nanoseconds(absl::Now() - start_time_));
  }

  void onLocalQueueReadyRead() {
    std::unique_ptr<wire::Message> msg;
    while (local_queue_->try_dequeue(msg)) {
      msg->visit(
        [&](wire::ChannelDataMsg& msg) {
          rx_bytes_total_ += msg.data->size();
          rx_packets_total_++;
          callbacks_->sendMessageLocal(std::move(msg));
        },
        [&](auto& msg) {
          callbacks_->sendMessageLocal(std::move(msg));
        });
    }
  }

  void onStatsTimerFired() {
    pomerium::extensions::ssh::ChannelEvent ev;
    auto* stats = ev.mutable_internal_channel_stats();
    stats->set_channel_id(channel_id_);
    populateChannelStats(stats->mutable_stats());
    event_callbacks_.sendChannelEvent(std::move(ev));
    stats_timer_->enableTimer(std::chrono::seconds(5));
  }

  uint32_t channel_id_{};
  Network::Address::SshEndpointMetadataConstSharedPtr metadata_;
  Envoy::Event::Dispatcher& local_dispatcher_;
  Envoy::Event::Dispatcher& remote_dispatcher_;
  MessageQueue* local_queue_;

  IoSocket::UserSpace::IoHandleImplPtr r_io_handle_;

  std::string server_name_;
  std::string path_;
  Envoy::Network::Address::InstanceConstSharedPtr downstream_address_;
  std::shared_ptr<const envoy::config::core::v3::Address> upstream_address_;
  ChannelEventCallbacks& event_callbacks_;

  bool channel_close_sent_{false};
  Event::SchedulableCallbackPtr local_queue_callback_;
  Event::SchedulableCallbackPtr error_callback_;
  Event::TimerPtr stats_timer_;

  uint64_t rx_bytes_total_{};
  uint64_t tx_bytes_total_{};
  uint64_t rx_packets_total_{};
  uint64_t tx_packets_total_{};
  absl::Time start_time_;

  absl::Status error_;
  bool send_eof_{false};

  absl::Mutex diagnostics_mu_;
  std::vector<std::unique_ptr<pomerium::extensions::ssh::Diagnostic>> diagnostics_ ABSL_GUARDED_BY(diagnostics_mu_);
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

namespace Envoy::Network {

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::InternalDownstreamChannel;
using Extensions::NetworkFilters::GenericProxy::Codec::StreamContext;

class InternalStreamSocketInterface : public SocketInterface,
                                      public Logger::Loggable<Logger::Id::filter> {
public:
  InternalStreamSocketInterface(std::shared_ptr<StreamTracker> stream_tracker,
                                std::vector<std::shared_ptr<const envoy::config::core::v3::Address>> upstream_addresses,
                                Event::Dispatcher& incoming_dispatcher)
      : stream_tracker_(std::move(stream_tracker)),
        upstream_addresses_(std::move(upstream_addresses)),
        incoming_dispatcher_(incoming_dispatcher) {
    ASSERT(stream_tracker_ != nullptr);
  }

  // SocketInterface
  IoHandlePtr socket(Socket::Type, Address::Type, Address::IpVersion,
                     bool, const SocketCreationOptions&) const override {
    throw Envoy::EnvoyException("not implemented");
  }
  IoHandlePtr socket(Socket::Type socket_type,
                     const Address::InstanceConstSharedPtr addr,
                     const SocketCreationOptions&) const override {
    ASSERT(socket_type == Socket::Type::Stream);
    const auto& addrImpl = dynamic_cast<const Address::InternalStreamAddressImpl&>(*addr);
    auto streamId = addrImpl.streamId();
    auto md = addrImpl.endpointMetadata();
    ENVOY_LOG(debug, "requesting downstream channel for stream {} via port {}", streamId, md->server_port().value());
    auto [local, remote] = IoHandleFactory::createIoHandlePair(std::make_unique<InternalStreamPassthroughState>());
    auto passthroughState = InternalStreamPassthroughState::fromIoHandle(*local);
    auto upstreamAddr = chooseAddress();

    passthroughState->setOnInitializedCallback(
      [this, streamId, md, io_handle = std::move(local), upstreamAddr = std::move(upstreamAddr)] mutable {
        stream_tracker_->tryLock(streamId, [this, streamId,
                                            md,
                                            io_handle = std::move(io_handle),
                                            upstreamAddr = std::move(upstreamAddr)](Envoy::OptRef<StreamContext> ctx) mutable {
          if (!ctx.has_value()) {
            ENVOY_LOG_MISC(error, "error requesting channel: stream with ID {} not found", streamId);
            io_handle->close(); // FIXME: not thread safe
            return;
          }
          ASSERT(ctx->connection().dispatcher().isThreadSafe());
          auto c = std::make_unique<InternalDownstreamChannel>(
            std::move(io_handle), md, upstreamAddr, ctx->eventCallbacks(), ctx->connection().dispatcher(), incoming_dispatcher_);
          auto id = ctx->streamCallbacks().startChannel(std::move(c), std::nullopt);
          if (!id.ok()) {
            ENVOY_LOG(error, "failed to start channel: {}", statusToString(id.status()));
            io_handle->close(); // FIXME: not thread safe
          }
          ENVOY_LOG(debug, "internal downstream channel started: {}", *id);
        });
      });
    return std::move(remote);
  }
  bool ipFamilySupported(int) override { return true; }

private:
  std::shared_ptr<const envoy::config::core::v3::Address> chooseAddress() const {
    auto addr = upstream_addresses_[round_robin_index_];
    round_robin_index_ = (round_robin_index_ + 1) % upstream_addresses_.size();
    return addr;
  }
  mutable std::shared_ptr<StreamTracker> stream_tracker_;
  std::vector<std::shared_ptr<const envoy::config::core::v3::Address>> upstream_addresses_;
  Event::Dispatcher& incoming_dispatcher_;
  mutable size_t round_robin_index_{0};
};

class SshTunnelClientConnectionFactory : public ClientConnectionFactory,
                                         public Logger::Loggable<Logger::Id::connection> {
public:
  ~SshTunnelClientConnectionFactory() override = default;

  // Config::UntypedFactory
  std::string name() const override { return "ssh_stream"; }

  // Network::ClientConnectionFactory
  ClientConnectionPtr
  createClientConnection(Event::Dispatcher& dispatcher,
                         Address::InstanceConstSharedPtr address,
                         Address::InstanceConstSharedPtr source_address,
                         TransportSocketPtr&& transport_socket,
                         const ConnectionSocket::OptionsSharedPtr& options,
                         const TransportSocketOptionsConstSharedPtr& transport_options) override {
    auto internalAddrFactory = std::dynamic_pointer_cast<const Address::InternalStreamAddressImpl>(address);
    auto internalAddr = Address::InternalStreamAddressImpl::createFromFactoryAddress(internalAddrFactory, dispatcher);
    return std::make_unique<ClientConnectionImpl>(
      dispatcher, internalAddr, source_address, std::move(transport_socket), options, transport_options);
  }
};
REGISTER_FACTORY(SshTunnelClientConnectionFactory, ClientConnectionFactory);

} // namespace Envoy::Network

namespace Envoy::Upstream {

InternalStreamSocketInterfaceFactory::InternalStreamSocketInterfaceFactory(
  std::shared_ptr<StreamTracker> stream_tracker,
  const envoy::config::endpoint::v3::ClusterLoadAssignment& load_assignment)
    : stream_tracker_(stream_tracker) {
  for (const auto& endpoint : load_assignment.endpoints()) {
    for (const auto& lb_endpoint : endpoint.lb_endpoints()) {
      upstream_addresses_.push_back(std::make_shared<const envoy::config::core::v3::Address>(
        lb_endpoint.endpoint().address()));
    }
  }
}

std::unique_ptr<Network::SocketInterface>
InternalStreamSocketInterfaceFactory::createSocketInterface(Event::Dispatcher& connection_dispatcher) {
  return std::make_unique<Network::InternalStreamSocketInterface>(stream_tracker_, upstream_addresses_, connection_dispatcher);
}

class InternalStreamHost : public HostImpl {
public:
  static absl::StatusOr<HostSharedPtr>
  create(stream_id_t id,
         Network::Address::SshEndpointMetadataConstSharedPtr metadata,
         ClusterInfoConstSharedPtr cluster_info,
         std::shared_ptr<InternalStreamSocketInterfaceFactory> socket_interface_factory) {
    absl::Status creation_status = absl::OkStatus();
    auto ret = absl::WrapUnique(new InternalStreamHost(creation_status, id, metadata, cluster_info, socket_interface_factory));
    RETURN_IF_NOT_OK(creation_status);

    return ret;
  }

protected:
  InternalStreamHost(absl::Status& creation_status,
                     stream_id_t stream_id,
                     Network::Address::SshEndpointMetadataConstSharedPtr metadata,
                     ClusterInfoConstSharedPtr cluster_info,
                     std::shared_ptr<InternalStreamSocketInterfaceFactory> socket_interface_factory)
      : HostImpl(creation_status,
                 cluster_info,
                 fmt::format("ssh:{}", stream_id),
                 std::make_shared<Network::Address::InternalStreamAddressImpl>(stream_id, metadata, socket_interface_factory),
                 nullptr,
                 nullptr,
                 1, // weight
                 envoy::config::core::v3::Locality().default_instance(),
                 envoy::config::endpoint::v3::Endpoint::HealthCheckConfig().default_instance(),
                 0, // priority class (only 0 is used)
                 envoy::config::core::v3::HEALTHY) {}
};

absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
SshReverseTunnelCluster::create(const envoy::config::cluster::v3::Cluster& cluster,
                                const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                                ClusterFactoryContext& cluster_context) {
  absl::Status creation_status = absl::OkStatus();
  // make a copy of the cluster config, clearing the original cluster load assignment
  envoy::config::cluster::v3::Cluster clone;
  clone.CopyFrom(cluster);
  clone.clear_load_assignment();
  auto ret = absl::WrapUnique(new SshReverseTunnelCluster(clone, proto_config, cluster.load_assignment(),
                                                          cluster_context, creation_status));
  RETURN_IF_NOT_OK(creation_status);
  return ret;
}

SshReverseTunnelCluster::SshReverseTunnelCluster(const envoy::config::cluster::v3::Cluster& cluster,
                                                 const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                                                 const envoy::config::endpoint::v3::ClusterLoadAssignment& load_assignment,
                                                 ClusterFactoryContext& cluster_context,
                                                 absl::Status& creation_status)
    : ClusterImplBase(cluster, cluster_context, creation_status),
      Envoy::Config::SubscriptionBase<envoy::config::endpoint::v3::ClusterLoadAssignment>(
        cluster_context.messageValidationVisitor(), "cluster_name"),
      cluster_(cluster),
      server_context_(cluster_context.serverFactoryContext()),
      config_(proto_config),
      stream_tracker_(StreamTracker::fromContext(cluster_context.serverFactoryContext())),
      socket_interface_factory_(std::make_shared<InternalStreamSocketInterfaceFactory>(stream_tracker_, load_assignment)),
      dispatcher_(cluster_context.serverFactoryContext().mainThreadDispatcher()) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  RETURN_ONLY_IF_NOT_OK_REF(creation_status);

  if (Runtime::runtimeFeatureEnabled(
        "envoy.reloadable_features.xdstp_based_config_singleton_subscriptions")) {
    auto subscription =
      cluster_context
        .serverFactoryContext()
        .xdsManager()
        .subscribeToSingletonResource(edsServiceName(),
                                      proto_config.eds_config(),
                                      Grpc::Common::typeUrl(getResourceName()),
                                      info_->statsScope(),
                                      *this, resource_decoder_, {});
    SET_AND_RETURN_IF_NOT_OK(subscription.status(), creation_status);
    eds_subscription_ = std::move(subscription).value();
  } else {
    auto subscription =
      cluster_context
        .serverFactoryContext()
        .clusterManager()
        .subscriptionFactory()
        .subscriptionFromConfigSource(proto_config.eds_config(),
                                      Grpc::Common::typeUrl(getResourceName()),
                                      info_->statsScope(),
                                      *this, resource_decoder_, {});
    SET_AND_RETURN_IF_NOT_OK(subscription.status(), creation_status);
    eds_subscription_ = std::move(subscription).value();
  }
}

void SshReverseTunnelCluster::startPreInit() {
  ENVOY_LOG(info, "starting EDS subscription (cluster={})", cluster_.name());
  eds_subscription_->start({info_->name()});
}

absl::Status SshReverseTunnelCluster::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                                                     const std::string&) {
  if (resources.empty()) {
    ENVOY_LOG(info, "Missing ClusterLoadAssignment for {} in onConfigUpdate()", edsServiceName());
    info_->configUpdateStats().update_empty_.inc();
    onPreInitComplete();
    return absl::OkStatus();
  }
  if (resources.size() != 1) {
    return absl::InvalidArgumentError(
      fmt::format("Unexpected EDS resource length: {}", resources.size()));
  }
  ENVOY_LOG(info, "received EDS update for cluster {}", edsServiceName());
  const auto& cluster_load_assignment =
    dynamic_cast<const envoy::config::endpoint::v3::ClusterLoadAssignment&>(resources[0].get().resource());
  if (cluster_load_assignment.cluster_name() != edsServiceName()) {
    return absl::InvalidArgumentError(fmt::format("Unexpected EDS cluster (expecting {}): {}",
                                                  edsServiceName(),
                                                  cluster_load_assignment.cluster_name()));
  }

  info_->configUpdateStats().update_success_.inc();
  return update(cluster_load_assignment);
}

absl::Status SshReverseTunnelCluster::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                                                     const Protobuf::RepeatedPtrField<std::string>&,
                                                     const std::string&) {
  return onConfigUpdate(added_resources, "");
}

void SshReverseTunnelCluster::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason reason, const EnvoyException* ex) {
  switch (reason) {
  case Config::ConfigUpdateFailureReason::ConnectionFailure:
    ENVOY_LOG(error, "EDS config update failed for cluster {}: connection failure ", edsServiceName());
    break;
  case Config::ConfigUpdateFailureReason::FetchTimedout:
    ENVOY_LOG(error, "EDS config update failed for cluster {}: fetch timeout", edsServiceName());
    break;
  case Config::ConfigUpdateFailureReason::UpdateRejected:
    ASSERT(ex != nullptr);
    ENVOY_LOG(error, "EDS config update failed for cluster {}: update rejected: {}", edsServiceName(), ex->what());
    break;
  }

  info_->configUpdateStats().update_failure_.inc();
  onPreInitComplete();
}

absl::Status SshReverseTunnelCluster::update(const envoy::config::endpoint::v3::ClusterLoadAssignment& cluster_load_assignment) {
  // only using one priority here (0)
  constexpr uint32_t priority = 0;
  const auto& hostSet = priority_set_.getOrCreateHostSet(priority).hosts();

  const auto& hostMap = priority_set_.crossPriorityHostMap();
  std::unordered_map<std::string, envoy::config::endpoint::v3::LbEndpoint> updatedEndpoints{};
  for (const auto& locality_lb_endpoint : cluster_load_assignment.endpoints()) {
    for (const auto& lb_endpoint : locality_lb_endpoint.lb_endpoints()) {
      updatedEndpoints.insert({lb_endpoint.endpoint().address().socket_address().address(), lb_endpoint});
    }
  }

  HostVector hostsToAdd;
  HostVector hostsToRemove;
  for (const auto& [key, value] : *hostMap) {
    if (!updatedEndpoints.contains(key)) {
      hostsToRemove.push_back(value);
    }
  }
  for (const auto& [endpointName, endpointData] : updatedEndpoints) {
    auto endpointNameView = std::string_view(endpointName);
    if (!hostMap->contains(endpointNameView)) {
      constexpr auto prefix = "ssh:"sv;
      if (!endpointNameView.starts_with(prefix)) {
        return absl::InternalError("invalid lb endpoint name '{}' (expecting format 'ssh:<id>')");
      }
      endpointNameView.remove_prefix(prefix.size());
      stream_id_t streamId{};
      if (!absl::SimpleAtoi(endpointNameView, &streamId)) {
        return absl::InternalError("bug: invalid lb endpoint name (expecting stream ID)");
      }

      auto metadata = std::make_shared<pomerium::extensions::ssh::EndpointMetadata>();
      const auto& typedMetadata = endpointData.metadata().typed_filter_metadata();
      if (auto it = typedMetadata.find("com.pomerium.ssh.endpoint"); it != typedMetadata.end()) {
        auto ok = it->second.UnpackTo(metadata.get());
        RELEASE_ASSERT(ok, "bug: invalid endpoint metadata");
      }

      auto newHost = InternalStreamHost::create(streamId, metadata, info_, socket_interface_factory_);
      if (!newHost.ok()) {
        return statusf("failed to create host for stream ID: {}", newHost.status());
      }
      hostsToAdd.push_back(std::move(newHost).value());
    }
  }

  auto filteredHostSetCopy = std::make_shared<HostVector>();
  // copy all the existing hosts, except those that have been removed
  std::copy_if(hostSet.begin(), hostSet.end(), std::back_inserter(*filteredHostSetCopy),
               [&](const HostSharedPtr& host) {
                 return !std::ranges::contains(hostsToRemove, host);
               });
  // copy all the new hosts
  std::copy(hostsToAdd.begin(), hostsToAdd.end(), std::back_inserter(*filteredHostSetCopy));

  ENVOY_LOG(info, "updating endpoints for cluster {}: {} added, {} removed, {} total", edsServiceName(),
            hostsToAdd.size(), hostsToRemove.size(), filteredHostSetCopy->size());
  priority_set_.updateHosts(priority,
                            HostSetImpl::partitionHosts(filteredHostSetCopy, HostsPerLocalityImpl::empty()), {},
                            std::move(hostsToAdd),
                            std::move(hostsToRemove),
                            server_context_.api().randomGenerator().random(),
                            std::nullopt, std::nullopt);

  onPreInitComplete(); // the first valid update will complete cluster initialization
  return absl::OkStatus();
}

SshReverseTunnelClusterFactory::SshReverseTunnelClusterFactory()
    : ConfigurableClusterFactoryBase("envoy.clusters.ssh_reverse_tunnel") {}

absl::StatusOr<std::pair<Upstream::ClusterImplBaseSharedPtr, Upstream::ThreadAwareLoadBalancerPtr>>
SshReverseTunnelClusterFactory::createClusterWithConfig(const envoy::config::cluster::v3::Cluster& cluster,
                                                        const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                                                        Upstream::ClusterFactoryContext& context) {
  auto c = SshReverseTunnelCluster::create(cluster, proto_config, context);
  if (!c.ok()) {
    return c.status();
  }
  return {{std::move(c).value(), nullptr}};
}

REGISTER_FACTORY(SshReverseTunnelClusterFactory, ClusterFactory);

} // namespace Envoy::Upstream