#include "source/extensions/filters/network/ssh/reverse_tunnel.h"
#include "source/common/status.h"
#include "source/common/math.h"
#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/socks5.h"
#include "source/extensions/filters/network/ssh/stream_address.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include <cstddef>

#pragma clang unsafe_buffer_usage begin
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.validate.h"
#include "source/common/network/connection_impl.h"
#include "source/common/network/connection_socket_impl.h"
#include "envoy/network/client_connection_factory.h"
#include "source/common/grpc/common.h"
#include "source/common/stream_info/filter_state_impl.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#include "readerwriterqueue/readerwriterqueue.h"
#pragma clang diagnostic pop
#pragma clang unsafe_buffer_usage end

using Envoy::Extensions::IoSocket::UserSpace::IoHandleFactory;

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr auto EventTypeMask = Event::FileReadyType::Closed | Event::FileReadyType::Read | Event::FileReadyType::Write;

using top_level_queue_message = wire::sub_message<
  wire::ChannelWindowAdjustMsg,
  wire::ChannelDataMsg,
  wire::ChannelEOFMsg,
  wire::ChannelCloseMsg>;
using QueueMessage = wire::BasicMessage<top_level_queue_message>;
using MessageQueue = moodycamel::ReaderWriterQueue<std::unique_ptr<QueueMessage>>;

class RemoteStreamHandlerCallbacks {
public:
  virtual ~RemoteStreamHandlerCallbacks() = default;
  virtual void scheduleQueueCallback() PURE;
  virtual void scheduleErrorCallback(absl::Status error, bool send_eof) PURE;
};

class RemoteStreamHandler : public Logger::Loggable<Logger::Id::filter>,
                            public Event::DeferredDeletable,
                            public Network::ConnectionCallbacks,
                            public Socks5ChannelCallbacks {
public:
  RemoteStreamHandler(IoSocket::UserSpace::IoHandleImplPtr io_handle,
                      Envoy::Event::Dispatcher& remote_dispatcher,
                      ReverseTunnelStats& reverse_tunnel_stats,
                      const pomerium::extensions::ssh::EndpointMetadata& host_metadata,
                      std::shared_ptr<const envoy::config::core::v3::Address> upstream_address)
      : io_handle_(std::move(io_handle)),
        remote_dispatcher_(remote_dispatcher),
        reverse_tunnel_stats_(reverse_tunnel_stats),
        metadata_(std::make_unique<pomerium::extensions::ssh::EndpointMetadata>(host_metadata)),
        upstream_address_(upstream_address) {
    ASSERT(upstream_address_ != nullptr);
    remote_queue_callback_ = remote_dispatcher_.createSchedulableCallback([this] {
      onRemoteQueueReadyRead();
    });
  }

  void initialize(RemoteStreamHandlerCallbacks& callbacks,
                  const wire::ChannelOpenConfirmationMsg& confirm,
                  MessageQueue** local_queue) {
    peer_state_ = {
      .callbacks = &callbacks,
      .id = confirm.recipient_channel,
      .max_packet_size = confirm.max_packet_size,
      .upstream_window = confirm.initial_window_size,
    };
    *local_queue = &local_queue_;

    // The remote dispatcher could be running concurrently, but it won't pick up this callback
    // until after the next time it acquires post_lock_ (see dispatcher_impl.cc). Because this call
    // to post() adds the callback to the queue while holding post_lock_, the write to peer_state_
    // happens-before the callback is invoked (which requires acquiring the lock again), where
    // initialized_ is set to true. Then, as long as initialized_ is only read/written in one
    // thread, a read of true on initialized_ will guarantee that reads on peer_state_ will observe
    // the above write.
    remote_dispatcher_.post([this] {
      initialized_ = true;
      // First check if the socket has been closed
      if (socket_closed_) {
        ENVOY_LOG(debug, "channel {}: downstream closed before initialization");
        onError(absl::CancelledError("downstream closed"));
        return;
      }
      ENVOY_LOG(debug, "channel {}: remote stream handler initialized", peer_state_.id);
      bool isDynamic = metadata_->server_port().is_dynamic();
      if (isDynamic) {
        ENVOY_LOG(debug, "channel {}: starting socks5 handshake", peer_state_.id);
        startSocks5Handshake();
        initializeFileEvents<Event::FileReadyType::Closed>();
      } else {
        initializeFileEvents<Event::FileReadyType::Closed | Event::FileReadyType::Read | Event::FileReadyType::Write>();
      }
      // If there were any messages queued while waiting for initialized_, process them now.
      remote_queue_callback_->scheduleCallbackCurrentIteration();
    });
  }
  static void detach(std::unique_ptr<RemoteStreamHandler> self) {
    self->detach_lock_.Lock();
    self->detached_ = true;
    self->detach_lock_.Unlock();
    self->remote_dispatcher_.post([self = std::move(self)] mutable {
      self->onDetached(std::move(self));
    });
  }

  void enqueueMessage(std::unique_ptr<QueueMessage> msg) {
    bool ok = remote_queue_.enqueue(std::move(msg));
    ASSERT(ok);
    remote_queue_callback_->scheduleCallbackNextIteration();
  }

private:
  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override {
    // These events are from the perspective of the downstream client connection, so LocalClose
    // means the downstream closed the connection, and RemoteClose means the upstream (us) closed
    // the connection.
    if (event == Network::ConnectionEvent::LocalClose ||
        event == Network::ConnectionEvent::RemoteClose) {
      // This is the last event received; the downstream connection will be destroyed and it is
      // safe to delete this object.
      socket_closed_ = true;
      if (!initialized_) {
        // Downstream closed before initialization
        ENVOY_LOG(debug, "downstream closed before initialization");
        return;
      }
      if (window_buffer_.length() > 0) {
        ENVOY_LOG(debug, "channel {}: downstream closed early, dropping {} bytes",
                  peer_state_.id, window_buffer_.length());
        window_buffer_.drain(window_buffer_.length());
      } else {
        ENVOY_LOG(debug, "channel {}: downstream closed");
      }
      // If we are already detached, submit for deletion. Otherwise, we need to raise an error and
      // wait to become detached.
      detach_lock_.Lock();
      if (detached_) {
        detach_lock_.Unlock();
        remote_dispatcher_.deferredDelete(std::move(detached_self_));
        return;
      }
      detach_lock_.Unlock();

      onError(absl::CancelledError("downstream closed"));
    }
  }

  // Network::ConnectionCallbacks
  void onAboveWriteBufferHighWatermark() override {
    // Called when downstream flow control is enabled via read path buffer watermarks.
    // We don't really have to do anything here, the downstream connection will automatically
    // apply backpressure until the upstream allows enough data to be written.
    reverse_tunnel_stats_.downstream_flow_control_high_watermark_activated_total_.inc();
  }

  // Network::ConnectionCallbacks
  void onBelowWriteBufferLowWatermark() override {
    reverse_tunnel_stats_.downstream_flow_control_low_watermark_activated_total_.inc();
  }

  void onError(absl::Status err) {
    ASSERT(initialized_);
    upstream_error_ = true;
    ENVOY_LOG(debug, "channel {}: remote error: {}", peer_state_.id, err);

    bool sendEof = false;
    if (socks5_handshaker_ != nullptr) {
      // If an error occured in the middle of the socks5 handshake, we have to send an EOF message
      // to the client.
      sendEof = true;
    }

    detach_lock_.Lock();
    if (!detached_) {
      ENVOY_LOG(debug, "channel {}: scheduling error callback", peer_state_.id);
      peer_state_.callbacks->scheduleErrorCallback(err, sendEof);
    } else {
      ENVOY_LOG(debug, "channel {}: not scheduling error callback (detached)", peer_state_.id);
    }
    detach_lock_.Unlock();
  }

  void onDetached(std::unique_ptr<RemoteStreamHandler> self) {
    // This object is now keeping itself alive. Once the remote queue is fully
    // drained, then it should submit itself for deletion.

    // Cancel the queue callback to make sure it doesn't fire again after we run it manually.
    remote_queue_callback_->cancel();

    // If the socket is closed, there is nothing left to do. This happens when we had previously
    // received a socket close event but were not detached yet (and had to wait for the channel
    // to be closed).
    if (socket_closed_) {
      remote_dispatcher_.deferredDelete(std::move(self));
      return;
    }

    // If the io handle is still open, it may still contain channel data we need to write, and it
    // also might end with a channel close message. We need to drain all messages from the queue,
    // ensure we have sent the shutdown event, and wait until the downstream response is fully
    // complete before closing.
    onRemoteQueueReadyRead();
    if (!received_channel_close_) {
      // If we didn't see a channel close, then shutdown() has not yet been called on the io handle.
      ENVOY_LOG(debug, "channel {}: local peer exited without sending a ChannelClose message");
    }
    // Close it for reading and writing, since reads are impossible
    io_handle_->close();

    // If we did receive a channel close, allow the response to be received by the downstream.
    // Once that happens, we will receive the socket close event, where the deferred deletion is
    // submitted.
    detached_self_ = std::move(self);
  }

  void onFileEvent(uint32_t events) {
    ASSERT(initialized_);
    ASSERT(remote_dispatcher_.isThreadSafe());
    ENVOY_LOG(trace, "channel {}: file events: {}", peer_state_.id, events);
    if ((events & Envoy::Event::FileReadyType::Read) != 0) {
      readReady();
    }

    // Note: "Closed" means closed for reading. If we also received a read event just now, this
    // signals EOF. The underlying connection may or may not be closed after this.
    if ((events & Envoy::Event::FileReadyType::Closed) != 0) {
      // If we get a close event, then the io handle has received EOF from the downstream.
      // However, there may still pending data in the io handle's read buffer which needs to be
      // sent before the EOF.
      // Even if a read event was received just now, upstream window space may have been exhausted
      // while reading from the io handle without draining it completely, so we will have to wait
      // for additional window updates from the upstream. Only when all data has been read should
      // the EOF be sent.
      // Note: getWriteBuffer() returns the read buffer (it is normally called by the peer).
      if (!downstream_eof_ && io_handle_->getWriteBuffer()->length() == 0) {
        // Only send this once since additional write events could be received if the downstream
        // is half-closed but the upstream still has data to write.
        downstream_eof_ = true;
        sendUpstreamEOF();
      }
    }

    if ((events & Envoy::Event::FileReadyType::Write) != 0) {
      if (!io_handle_->isPeerWritable()) {
        return;
      }
      if (downstream_write_disabled_) {
        downstream_write_disabled_ = false;
        ENVOY_LOG(debug, "channel {}: flow control: downstream write enabled", peer_state_.id);
        if (upstream_error_) {
          ENVOY_LOG(debug, "channel {}: flow control: not re-enabling window adjustments due to upstream error",
                    peer_state_.id);
        } else {
          // Don't need to (potentially) send a window adjustment if the channel is about to be
          // closed anyway. Note that close/eof messages don't consume window space.
          ENVOY_LOG(debug, "channel {}: flow control: re-enabling window adjustments", peer_state_.id);
          reverse_tunnel_stats_.upstream_flow_control_window_adjustment_resumed_total_.inc();

          // While the downstream was write-disabled, local window adjustments were paused, so check
          // if we need to send a window adjustment now. This is otherwise only checked on upstream
          // writes, but if the upstream ran out of window space it would be waiting for a window
          // adjustment before sending anything else.
          if (localWindowBelowThreshold()) {
            resizeLocalWindow();
          }
        }
      }
      writeReady();
    }
  }

  void onRemoteQueueReadyRead() {
    ASSERT(remote_dispatcher_.isThreadSafe());
    if (!initialized_) {
      ENVOY_LOG(debug, "channel {}: skipping remote queue read before initialization", peer_state_.id);
      return;
    }
    std::unique_ptr<QueueMessage> msgPtr;
    while (!upstream_error_ && remote_queue_.try_dequeue(msgPtr)) {
      QueueMessage& msg = *msgPtr;
      msg.visit(
        [&](wire::ChannelDataMsg& msg) {
          auto size = static_cast<uint32_t>(msg.data->size());
          if (size > wire::ChannelMaxPacketSize) {
            onError(absl::InvalidArgumentError(fmt::format("channel {}: packet too large",
                                                           peer_state_.id)));
            return;
          } else if (size == 0) {
            return;
          }
          // subtract from the local window
          if (sub_overflow(&local_window_, size)) {
            // the upstream wrote more bytes than allowed by the local window
            ENVOY_LOG(debug, "channel {}: flow control: remote exceeded local window", peer_state_.id);
            onError(absl::InvalidArgumentError(fmt::format("channel {}: local window exceeded", peer_state_.id)));
            return;
          }
          // process the channel data message
          ENVOY_LOG(debug, "channel {}: read {} bytes from upstream", peer_state_.id, size);
          if (auto stat = readChannelData(msg); !stat.ok()) {
            onError(stat);
            return;
          }
          // check if we need to increase the local window
          if (localWindowBelowThreshold()) {
            if (local_window_ == 0) {
              // only happens once; we check for empty messages above, so there must have been
              // nonzero local window
              reverse_tunnel_stats_.upstream_flow_control_local_window_exhausted_total_.inc();
            }
            if (downstream_write_disabled_) {
              // Don't increase the window size for the upstream if the downstream is not writable.
              // We can queue at most one full window of data, after which the upstream will stop
              // writing until we increase the window size.
              ENVOY_LOG_EVERY_POW_2(debug, "channel {}: flow control: not increasing local window size: "
                                           "downstream is not writable",
                                    peer_state_.id);
              return;
            }
            resizeLocalWindow();
          }
        },
        [&](wire::ChannelWindowAdjustMsg& msg) {
          if (add_overflow(&peer_state_.upstream_window, *msg.bytes_to_add)) {
            onError(absl::InvalidArgumentError("invalid window adjust"));
            return;
          }
          ENVOY_LOG(debug, "channel {}: flow control: remote window adjusted by {} bytes", peer_state_.id, *msg.bytes_to_add);
          // If we had disabled read events due to running out of remote window space, re-enable
          if ((enabled_file_events_ & Event::FileReadyType::Read) == 0) {
            ENVOY_LOG(debug, "channel {}: upstream window restored, enabling read events", peer_state_.id);
            reverse_tunnel_stats_.downstream_flow_control_remote_window_restored_total_.inc();
            // This will schedule the read event callback
            enableFileEvents<Event::FileReadyType::Read>();
          }
          return;
        },
        [&](wire::ChannelEOFMsg&) {
        },
        [&](wire::ChannelCloseMsg&) {
          received_channel_close_ = true;
          // Note: we won't intentionally close the io handle ourselves until this object is about
          // to be destroyed, and all messages have been read from the queue. However, it could
          // still be closed by the peer. shutdown() can only be called if the handle is open.
          if (io_handle_->isOpen()) {
            io_handle_->shutdown(ENVOY_SHUT_WR);
          }
        });
    }
  }

  bool localWindowBelowThreshold() {
    return local_window_ < wire::ChannelWindowSize / 2;
  }

  void resizeLocalWindow() {
    // Adjust the window to return to the default limit
    uint32_t delta = wire::ChannelWindowSize - local_window_;
    ASSERT(delta > 0);
    ENVOY_LOG(debug, "channel {}: flow control: increasing local window size ({} -> {})",
              peer_state_.id, local_window_, local_window_ + delta);
    if (local_window_ == 0) {
      reverse_tunnel_stats_.upstream_flow_control_local_window_restored_total_.inc();
    }
    local_window_ += delta;
    has_resized_local_window_ = true;

    enqueueLocalMessage(std::make_unique<QueueMessage>(wire::ChannelWindowAdjustMsg{
      .recipient_channel = peer_state_.id,
      .bytes_to_add = delta,
    }));
  }

  void sendUpstreamEOF() {
    enqueueLocalMessage(std::make_unique<QueueMessage>(wire::ChannelEOFMsg{
      .recipient_channel = peer_state_.id,
    }));
  }

  void readReady() {
    ASSERT(initialized_);
    ASSERT(remote_dispatcher_.isThreadSafe());

    // Read from the transport socket and encapsulate the data into a ChannelData message, then
    // write it on the channel

    ASSERT(read_buffer_.length() == 0);

    // Repeatedly read from the io handle until it returns EAGAIN or we run out of upstream window
    // space. The Read event is only fired when new data arrives, and the buffer may contain more
    // bytes than the maximum that can be read by a single call to read() (131072 by default).
    // For simplicity, we read up to the max packet size then fully drain read_buffer_ on each
    // iteration.
    // TODO: this could be more efficient
    while (peer_state_.upstream_window > 0) {
      auto r = io_handle_->read(read_buffer_, std::min(peer_state_.max_packet_size, peer_state_.upstream_window));
      // Note: IO errors are limited in the user space io handle; anything causing an error here
      // would also trigger a close event. The only real error we would get here is "peer closed".
      if (r.wouldBlock()) {
        break;
      }
      if (r.return_value_ == 0) {
        break;
      }
      ASSERT(r.return_value_ <= peer_state_.upstream_window); // sanity check
      ENVOY_LOG(trace, "channel {}: upstream window {}->{}",
                peer_state_.id,
                peer_state_.upstream_window,
                peer_state_.upstream_window - static_cast<uint32_t>(r.return_value_));
      peer_state_.upstream_window -= static_cast<uint32_t>(r.return_value_);
      bytes data;
      data.resize(read_buffer_.length());
      read_buffer_.copyOut(0, data.size(), data.data());
      read_buffer_.drain(read_buffer_.length());
      ENVOY_LOG(debug, "channel {}: read {} bytes from downstream", peer_state_.id, r.return_value_);
      enqueueLocalMessage(std::make_unique<QueueMessage>(wire::ChannelDataMsg{
        .recipient_channel = peer_state_.id,
        .data = std::move(data),
      }));
    }

    if (peer_state_.upstream_window == 0) {
      // If we are completely out of upstream window space, disable read events until we receive
      // a window update.
      ENVOY_LOG(debug, "channel {}: upstream window exhausted, disabling read events", peer_state_.id);
      disableFileEvents<Event::FileReadyType::Read>();
      reverse_tunnel_stats_.downstream_flow_control_remote_window_exhausted_total_.inc();
    }
  }

  void writeReady() {
    ASSERT(initialized_);
    ASSERT(remote_dispatcher_.isThreadSafe());
    // Flush data from the window buffer to the downstream until the buffer is empty or the
    // downstream high watermark is reached
    while (window_buffer_.length() > 0) {
      auto r = io_handle_->write(window_buffer_);
      if (!r.ok()) {
        RELEASE_ASSERT(r.wouldBlock(), "");
        downstream_write_disabled_ = true;
        // Downstream write buffer high watermark activated
        ENVOY_LOG(debug, "channel {}: flow control: downstream write disabled");
        reverse_tunnel_stats_.upstream_flow_control_window_adjustment_paused_total_.inc();
        return;
      }
      ENVOY_LOG(debug, "channel {}: read {} bytes from downstream", peer_state_.id, r.return_value_);
    }
  }

  void startSocks5Handshake() {
    socks5_handshaker_ = std::make_unique<Socks5ClientHandshaker>(*this, upstream_address_);
    socks5_handshaker_->startHandshake();
  }

  // Socks5ChannelCallbacks
  void writeChannelData(bytes&& data) override {
    ASSERT(initialized_);
    enqueueLocalMessage(std::make_unique<QueueMessage>(wire::ChannelDataMsg{
      .recipient_channel = peer_state_.id,
      .data = std::move(data),
    }));
  }

  void enqueueLocalMessage(std::unique_ptr<QueueMessage> msg) {
    ASSERT(initialized_);
    ASSERT(remote_dispatcher_.isThreadSafe());
    bool ok = local_queue_.enqueue(std::move(msg));
    ASSERT(ok);

    detach_lock_.Lock(); // this lock is always uncontended, except possibly during close
    if (!detached_) [[likely]] {
      peer_state_.callbacks->scheduleQueueCallback();
    }
    detach_lock_.Unlock();
  }

  absl::Status readChannelData(const wire::ChannelDataMsg& msg) {
    ASSERT(initialized_);
    window_buffer_.add(msg.data->data(), msg.data->size());
    return processWindowBuffer();
  }

  absl::Status processWindowBuffer() {
    if (socks5_handshaker_ != nullptr) {
      return processSocks5HandshakeData();
    }
    if (!downstream_write_disabled_ && !socket_closed_) [[likely]] {
      writeReady();
    }
    return absl::OkStatus();
  }

  absl::Status processSocks5HandshakeData() {
    ASSERT(socks5_handshaker_ != nullptr);
    if (auto stat = socks5_handshaker_->readChannelData(window_buffer_); !stat.ok()) {
      return statusf("socks5 handshake error: {}", stat);
    }

    auto&& result = socks5_handshaker_->result();
    if (!result.has_value()) {
      ENVOY_LOG(debug, "channel {}: socks5 handshake not complete", peer_state_.id);
      return absl::OkStatus();
    }

    socks5_handshaker_.reset();
    ENVOY_LOG(debug, "channel {}: socks5 handshake completed (server address: {})",
              peer_state_.id, result.value()->asString());
    if (io_handle_->isOpen()) {
      // We had only enabled close events before, enable read and write events now
      enableFileEvents<Event::FileReadyType::Read | Event::FileReadyType::Write>();
    }
    if (window_buffer_.length() == 0) {
      return absl::OkStatus();
    }
    // Continue if there is more data to be read past the socks5 handshake
    return processWindowBuffer();
  }

  template <auto E>
    requires ((E & EventTypeMask) == E)
  void initializeFileEvents() {
    enabled_file_events_ = static_cast<uint8_t>(E);
    io_handle_->initializeFileEvent(
      remote_dispatcher_,
      [this](uint32_t events) {
        onFileEvent(events);
        // errors returned from this callback are fatal
        return absl::OkStatus();
      },
      Event::PlatformDefaultTriggerType,
      enabled_file_events_);
  }

  template <auto E>
    requires ((E & EventTypeMask) == E)
  void enableFileEvents() {
    enabled_file_events_ |= static_cast<uint8_t>(E);
    io_handle_->enableFileEvents(enabled_file_events_);
  }

  template <auto E>
    requires ((E & EventTypeMask) == E)
  void disableFileEvents() {
    enabled_file_events_ &= ~static_cast<uint8_t>(E);
    io_handle_->enableFileEvents(enabled_file_events_);
  }

  struct PeerState {
    RemoteStreamHandlerCallbacks* callbacks{};
    uint32_t id{};
    uint32_t max_packet_size{};
    uint32_t upstream_window{};
  };

  bool initialized_ : 1 {false};
  bool received_channel_close_ : 1 {false};
  bool downstream_write_disabled_ : 1 {false};
  bool has_resized_local_window_ : 1 {false};
  bool socket_closed_ : 1 {false};
  bool upstream_error_ : 1 {false};
  bool downstream_eof_ : 1 {false};
  bool detached_ : 1 ABSL_GUARDED_BY(detach_lock_){false};
  uint8_t enabled_file_events_{};
  uint32_t local_window_{wire::ChannelWindowSize};
  IoSocket::UserSpace::IoHandleImplPtr io_handle_;
  // Stores peer info. This is only safe to access after observing initialized_==true.
  PeerState peer_state_{};

  absl::Mutex detach_lock_;
  Envoy::Event::Dispatcher& remote_dispatcher_;
  Event::SchedulableCallbackPtr remote_queue_callback_;
  std::unique_ptr<Socks5ClientHandshaker> socks5_handshaker_;
  ReverseTunnelStats& reverse_tunnel_stats_;
  std::unique_ptr<pomerium::extensions::ssh::EndpointMetadata> metadata_;
  std::shared_ptr<const envoy::config::core::v3::Address> upstream_address_;

  MessageQueue remote_queue_; // occupies 2 cache lines
  MessageQueue local_queue_;  // occupies 2 cache lines

  Buffer::OwnedImpl window_buffer_;
  Buffer::OwnedImpl read_buffer_;

  std::unique_ptr<RemoteStreamHandler> detached_self_;
};

class InternalDownstreamChannel final : public Channel,
                                        public RemoteStreamHandlerCallbacks,
                                        public Logger::Loggable<Logger::Id::filter> {
public:
  InternalDownstreamChannel(Envoy::Event::Dispatcher& local_dispatcher,
                            std::unique_ptr<RemoteStreamHandler> remote,
                            ChannelEventCallbacks& event_callbacks,
                            const pomerium::extensions::ssh::EndpointMetadata& host_metadata,
                            Network::HostDrainManager& host_drain_manager,
                            std::shared_ptr<const envoy::config::core::v3::Address> upstream_address,
                            std::shared_ptr<Network::InternalStreamPassthroughState> passthrough_state)
      : local_dispatcher_(local_dispatcher),
        local_queue_callback_(local_dispatcher_.createSchedulableCallback([this] {
          onLocalQueueReadyRead();
        })),
        remote_(std::move(remote)),
        event_callbacks_(event_callbacks),
        stats_timer_(local_dispatcher.createTimer([this] {
          onStatsTimerFired();
        })),
        error_callback_(local_dispatcher_.createSchedulableCallback([this] {
          onErrorCallback();
        })),
        metadata_(host_metadata),
        host_drain_callback_(host_drain_manager.addHostDrainCallback(local_dispatcher, [this] {
          onHostDraining();
        })),
        upstream_address_(upstream_address) {
    ASSERT(local_dispatcher_.isThreadSafe());
    loadPassthroughMetadata(passthrough_state);
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
    if (metadata_.matched_permission().requested_host().empty()) {
      // wildcard mode
      req.address_connected = "";
    } else {
      // use the original pattern as the address
      req.address_connected = metadata_.matched_permission().requested_host();
    }
    req.port_connected = metadata_.server_port().value();
    req.originator_address = downstream_address_->ip()->addressAsString(),
    req.originator_port = downstream_address_->ip()->port();

    wire::ChannelOpenMsg open{
      .sender_channel = channel_id_,
      .initial_window_size = wire::ChannelWindowSize,
      .max_packet_size = wire::ChannelMaxPacketSize,
      .request = std::move(req),
    };
    ENVOY_LOG(debug, "channel {}: flow control: local window initialized to {}", channel_id_, wire::ChannelWindowSize);

    callbacks.sendMessageLocal(std::move(open));
    return absl::OkStatus();
  }

  // RemoteStreamHandlerCallbacks
  void scheduleQueueCallback() final {
    // ASSERT(remote_dispatcher_.isThreadSafe());
    local_queue_callback_->scheduleCallbackNextIteration();
  }

  // RemoteStreamHandlerCallbacks
  void scheduleErrorCallback(absl::Status error, bool send_eof) final {
    // ASSERT(remote_dispatcher_.isThreadSafe());
    error_ = error;
    send_eof_ = send_eof;
    error_callback_->scheduleCallbackNextIteration();
  }

  // Local thread
  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&& confirm) override {
    if (host_draining_) {
      // See comment in onHostDraining() for details
      maybeSendChannelClose(absl::UnavailableError("host is draining"), false);
      return absl::OkStatus();
    }
    remote_->initialize(*this, confirm, &local_queue_);
    remote_initialized_ = true;

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
    // If the channel open fails, the following will occur in order:
    // 1. This object is destroyed (automatically by the connection service)
    // 2. The remote stream handler is detached
    // 3. The remote stream handler runs its detach routine in the remote thread. It sees that
    //    it has not been initialized, and that the io handle is still open. It will close the
    //    io handle and submit itself for deletion.
    return absl::OkStatus();
  }

  // Local thread
  absl::Status readMessage(wire::Message&& msg) override {
    return msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        tx_bytes_total_ += msg.data->size();
        tx_packets_total_++;
        remote_->enqueueMessage(std::make_unique<QueueMessage>(std::move(msg)));
        return absl::OkStatus();
      },
      [&](const wire::ChannelCloseMsg& msg) {
        ENVOY_LOG(debug, "channel {}: downstream closed", channel_id_);
        remote_->enqueueMessage(std::make_unique<QueueMessage>(std::move(msg)));
        maybeSendChannelClose(absl::OkStatus(), false);
        return absl::OkStatus();
      },
      [&](const wire::ChannelEOFMsg& msg) {
        maybeWarnOnEOF();
        remote_->enqueueMessage(std::make_unique<QueueMessage>(std::move(msg)));
        return absl::OkStatus();
      },
      [&](const wire::ChannelWindowAdjustMsg& msg) {
        remote_->enqueueMessage(std::make_unique<QueueMessage>(std::move(msg)));
        return absl::OkStatus();
      },
      [&](const auto&) {
        return absl::InvalidArgumentError(
          fmt::format("received unexpected message on forwarded-tcpip channel: {}",
                      msg.msg_type()));
      });
  }

private:
  void onLocalQueueReadyRead() {
    std::unique_ptr<QueueMessage> msg;
    while (local_queue_->try_dequeue(msg)) {
      msg->visit(
        [&](wire::ChannelDataMsg& msg) {
          rx_bytes_total_ += msg.data->size();
          rx_packets_total_++;
          ENVOY_LOG(trace, "channel {}: local queue read {} bytes (total: {})",
                    channel_id_, msg.data->size(), rx_bytes_total_);
          callbacks_->sendMessageLocal(std::move(msg));
        },
        [&](auto& msg) {
          callbacks_->sendMessageLocal(std::move(msg));
        });
    }
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
    maybeSendChannelClose(error_, send_eof_);
  }

  void maybeSendChannelClose(absl::Status status, bool send_eof) {
    if (channel_close_sent_) {
      ENVOY_LOG(debug, "channel {}: channel close already sent");
      return;
    }
    channel_close_sent_ = true;

    if (send_eof) {
      ENVOY_LOG(debug, "channel {}: sending eof", channel_id_);
      callbacks_->sendMessageLocal(wire::ChannelEOFMsg{
        .recipient_channel = channel_id_,
      });
    }
    if (!status.ok()) {
      ENVOY_LOG(debug, "channel {}: sending close: {}", channel_id_, statusToString(status));
    } else {
      ENVOY_LOG(debug, "channel {}: sending close", channel_id_);
    }
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
    for (const auto& diag : diagnostics_) {
      closed->add_diagnostics()->CopyFrom(diag);
    }
    event_callbacks_.sendChannelEvent(std::move(ev));
  }

  void populateChannelStats(pomerium::extensions::ssh::ChannelStats* stats) {
    stats->set_rx_bytes_total(rx_bytes_total_);
    stats->set_tx_bytes_total(tx_bytes_total_);
    stats->set_rx_packets_total(rx_packets_total_);
    stats->set_tx_packets_total(tx_packets_total_);
    // TODO: this should use the server's time system instead
    *stats->mutable_channel_duration() = Protobuf::util::TimeUtil::NanosecondsToDuration(absl::ToInt64Nanoseconds(absl::Now() - start_time_));
  }

  void onStatsTimerFired() {
    pomerium::extensions::ssh::ChannelEvent ev;
    auto* stats = ev.mutable_internal_channel_stats();
    stats->set_channel_id(channel_id_);
    populateChannelStats(stats->mutable_stats());
    event_callbacks_.sendChannelEvent(std::move(ev));
    stats_timer_->enableTimer(std::chrono::seconds(5));
  }

  void loadPassthroughMetadata(std::shared_ptr<Network::InternalStreamPassthroughState> passthrough_state) {
    RELEASE_ASSERT(passthrough_state->isInitialized(), "");

    envoy::config::core::v3::Metadata passthrough_metadata;
    StreamInfo::FilterStateImpl passthrough_filter_state{StreamInfo::FilterState::LifeSpan::Connection};

    passthrough_state->mergeInto(passthrough_metadata, passthrough_filter_state);

    auto* serverName = passthrough_filter_state.getDataReadOnly<RequestedServerName>(RequestedServerName::key());
    RELEASE_ASSERT(serverName != nullptr, "");
    server_name_ = serverName->value();

    auto* path = passthrough_filter_state.getDataReadOnly<RequestedPath>(RequestedPath::key());
    if (path != nullptr) {
      path_ = path->value();
    }

    auto* addr = passthrough_filter_state.getDataReadOnly<Network::AddressObject>(DownstreamSourceAddressFilterStateFactory::key());
    RELEASE_ASSERT(addr != nullptr, "");
    downstream_address_ = addr->address();
  }

  void maybeWarnOnEOF() {
    // If this is the first message received by the server, and we did not send a socks5
    // handshake, it is possible that the server was expecting us to. If the upstream server
    // simply failed to connect, we would have received a channel open failure instead.
    const auto& requestedHost = metadata_.matched_permission().requested_host();
    bool isFirstMsgReceived = tx_packets_total_ == 0;
    bool requestedHostHasWildcards = (requestedHost == "" || requestedHost == "localhost" ||
                                      requestedHost.contains("*") || requestedHost.contains("?"));
    if (isFirstMsgReceived && !metadata_.server_port().is_dynamic() && requestedHostHasWildcards) {
      pomerium::extensions::ssh::Diagnostic diag;
      diag.set_severity(pomerium::extensions::ssh::Diagnostic::Warning);
      diag.set_message("ssh client may be expecting dynamic port-forwarding");

      auto requestedPort = metadata_.matched_permission().requested_port();
      const auto& upstreamAddr = upstream_address_->socket_address().address();
      auto upstreamPort = upstream_address_->socket_address().port_value();
      if (requestedHost == "localhost") {
        // The -R syntax that sends 'localhost' is slightly different
        diag.add_hints(fmt::format("try requesting port 0 instead of {} (ex: '-R :0')", requestedPort));
        diag.add_hints(fmt::format("or, specify a local host:port (ex: '-R {}:{}:{}')",
                                   metadata_.server_port().value(),
                                   upstreamAddr, upstreamPort));
      } else {
        diag.add_hints(fmt::format("try requesting port 0 instead of {} (ex: '-R {}:0')",
                                   requestedPort, requestedHost));
        diag.add_hints(fmt::format("or, specify a local host:port (ex: '-R {}:{}:{}:{}')",
                                   requestedHost,
                                   metadata_.server_port().value(),
                                   upstreamAddr, upstreamPort));
      }
      diagnostics_.push_back(std::move(diag));
    }
  }

  void onHostDraining() {
    ASSERT(local_dispatcher_.isThreadSafe());
    // Called when the host for this connection has been removed from the pool of healthy hosts
    // available to the cluster. This may happen as a result of the host becoming unauthorized as
    // an upstream tunnel for the route, or if the upstream ssh client sent a cancel-tcpip-forward
    // request.

    // We might not have received the channel open confirmation (or failure) yet. If the host is
    // removed between the time the channel open is sent and the confirmation is received, there
    // is no channel *to* close, so it will instead be closed immediately once the confirmation
    // is received (and if the channel open fails, there is nothing to do anyway).

    host_draining_ = true;
    if (remote_initialized_) {
      maybeSendChannelClose(absl::UnavailableError("host is draining"), false);
    }
  }

  MessageQueue* local_queue_;
  Envoy::Event::Dispatcher& local_dispatcher_;
  Event::SchedulableCallbackPtr local_queue_callback_;
  uint64_t rx_bytes_total_{};
  uint64_t rx_packets_total_{};

  std::unique_ptr<RemoteStreamHandler> remote_;
  uint64_t tx_bytes_total_{};
  uint64_t tx_packets_total_{};
  absl::Time start_time_;
  ChannelEventCallbacks& event_callbacks_;
  Event::TimerPtr stats_timer_;
  uint32_t channel_id_{};
  bool channel_close_sent_{false};
  bool send_eof_{false};
  bool host_draining_{false};
  bool remote_initialized_{false};

  Event::SchedulableCallbackPtr error_callback_;
  absl::Status error_;
  std::vector<pomerium::extensions::ssh::Diagnostic> diagnostics_;

  pomerium::extensions::ssh::EndpointMetadata metadata_;
  Envoy::Common::CallbackHandlePtr host_drain_callback_;
  Envoy::Network::Address::InstanceConstSharedPtr downstream_address_;
  std::shared_ptr<const envoy::config::core::v3::Address> upstream_address_;
  std::string server_name_;
  std::string path_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

namespace Envoy::Network {

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::InternalDownstreamChannel;
using Extensions::NetworkFilters::GenericProxy::Codec::StreamContext;

class SshTunnelClientConnectionFactory : public ClientConnectionFactory,
                                         public Logger::Loggable<Logger::Id::connection> {
public:
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
    auto streamAddress = std::dynamic_pointer_cast<const Address::SshStreamAddress>(address);
    auto streamId = streamAddress->streamId();
    auto [local, remote] = IoHandleFactory::createIoHandlePair(std::make_unique<InternalStreamPassthroughState>());
    local->setWriteRequiresReadEventEnabled(true);
    remote->setWriteRequiresReadEventEnabled(true);
    auto passthroughState = InternalStreamPassthroughState::fromIoHandle(*local);

    auto remote_socket = std::make_unique<Network::ConnectionSocketImpl>(std::move(remote), source_address, address);
    auto clientConnection = std::make_unique<ClientConnectionImpl>(dispatcher, std::move(remote_socket), address, std::move(transport_socket), options, transport_options);
    RELEASE_ASSERT(passthroughState->isInitialized(), "invalid transport socket configuration");

    auto& hostContext = streamAddress->hostContext();
    auto upstreamAddr = hostContext.clusterContext().chooseUpstreamAddress();

    ENVOY_LOG(debug, "channel {}: starting remote stream handler");
    using Extensions::NetworkFilters::GenericProxy::Codec::RemoteStreamHandler;
    auto remoteStreamHandler = std::make_unique<RemoteStreamHandler>(std::move(local),
                                                                     dispatcher,
                                                                     hostContext.clusterContext().reverseTunnelStats(),
                                                                     hostContext.hostMetadata(),
                                                                     upstreamAddr);

    clientConnection->addConnectionCallbacks(*remoteStreamHandler);

    hostContext.clusterContext()
      .streamTracker()
      ->tryLock(streamId, [remoteStreamHandler = std::move(remoteStreamHandler),
                           upstreamAddr = std::move(upstreamAddr),
                           passthroughState,
                           hostContext = &hostContext,
                           streamId](Envoy::OptRef<StreamContext> ctx) mutable {
        if (!ctx.has_value()) {
          ENVOY_LOG_MISC(debug, "error requesting channel: stream with ID {} not found", streamId);
          RemoteStreamHandler::detach(std::move(remoteStreamHandler));
          return;
        }
        ASSERT(ctx->connection().dispatcher().isThreadSafe());
        auto c = std::make_unique<InternalDownstreamChannel>(ctx->connection().dispatcher(),
                                                             std::move(remoteStreamHandler),
                                                             ctx->eventCallbacks(),
                                                             hostContext->hostMetadata(),
                                                             hostContext->hostDrainManager(),
                                                             upstreamAddr,
                                                             passthroughState);
        auto id = ctx->streamCallbacks().startChannel(std::move(c), std::nullopt);
        if (!id.ok()) { // XXX test this case
          ENVOY_LOG(warn, "failed to start channel: {}", statusToString(id.status()));
        } else {
          ENVOY_LOG(debug, "internal downstream channel started: {}", *id);
        }
      });

    return std::move(clientConnection);
  }
};
REGISTER_FACTORY(SshTunnelClientConnectionFactory, ClientConnectionFactory);

} // namespace Envoy::Network

namespace Envoy::Upstream {

class HostContextImpl : public Network::HostContext {
public:
  HostContextImpl(Upstream::MetadataConstSharedPtr metadata,
                  Network::HostDrainManager& host_drain_manager,
                  Network::ReverseTunnelClusterContext& cluster_context)
      : host_drain_manager_(host_drain_manager),
        cluster_context_(cluster_context) {
    auto ok = metadata->typed_filter_metadata()
                .at("com.pomerium.ssh.endpoint")
                .UnpackTo(&metadata_);
    RELEASE_ASSERT(ok, "invalid endpoint metadata");
  }

  const pomerium::extensions::ssh::EndpointMetadata& hostMetadata() override { return metadata_; }
  Network::HostDrainManager& hostDrainManager() override { return host_drain_manager_; }
  Network::ReverseTunnelClusterContext& clusterContext() override { return cluster_context_; }

protected:
  pomerium::extensions::ssh::EndpointMetadata metadata_;
  Network::HostDrainManager& host_drain_manager_;
  Network::ReverseTunnelClusterContext& cluster_context_;
};

class InternalStreamHost : public Network::HostDrainManager,
                           public HostContextImpl,
                           public HostImpl {
public:
  static HostSharedPtr
  create(stream_id_t id,
         MetadataConstSharedPtr metadata,
         Network::ReverseTunnelClusterContext& cluster_context) {
    absl::Status creation_status = absl::OkStatus();
    // This can only fail if we pass HostImpl an invalid health check config or an invalid address,
    // both of which should not be possible.
    auto host = std::make_shared<InternalStreamHost>(creation_status, id, metadata, cluster_context);
    THROW_IF_NOT_OK_REF(creation_status);
    return host;
  }

  InternalStreamHost(absl::Status& creation_status,
                     stream_id_t stream_id,
                     MetadataConstSharedPtr metadata,
                     Network::ReverseTunnelClusterContext& cluster_context)
      : HostContextImpl(metadata, *this, cluster_context),
        HostImpl(creation_status,
                 cluster_context.clusterInfo(),
                 fmt::format("ssh:{}", stream_id),
                 std::make_shared<Network::Address::SshStreamAddress>(stream_id, *this),
                 metadata,
                 nullptr,
                 1, // weight
                 envoy::config::core::v3::Locality::default_instance(),
                 envoy::config::endpoint::v3::Endpoint::HealthCheckConfig::default_instance(),
                 0, // priority class (only 0 is used)
                 envoy::config::core::v3::HEALTHY) {
    setDisableActiveHealthCheck(true);
  }

  void setEdsHealthStatus(HealthStatus health_status) override {
    HostImpl::setEdsHealthStatus(health_status);
    if (health_status == HealthStatus::DRAINING) {
      runHostDrainCallbacks();
    }
  }
};

class ReverseTunnelClusterContextImpl : public Network::ReverseTunnelClusterContext {
public:
  ReverseTunnelClusterContextImpl(ClusterInfoConstSharedPtr cluster_info,
                                  std::shared_ptr<StreamTracker> stream_tracker,
                                  const envoy::config::endpoint::v3::ClusterLoadAssignment& load_assignment,
                                  ReverseTunnelStats& reverse_tunnel_stats)
      : cluster_info_(cluster_info),
        stream_tracker_(std::move(stream_tracker)),
        reverse_tunnel_stats_(reverse_tunnel_stats) {
    for (const auto& endpoint : load_assignment.endpoints()) {
      for (const auto& lb_endpoint : endpoint.lb_endpoints()) {
        upstream_addresses_.push_back(std::make_shared<const envoy::config::core::v3::Address>(
          lb_endpoint.endpoint().address()));
      }
    }
  }

  const ClusterInfoConstSharedPtr& clusterInfo() override { return cluster_info_; }
  std::shared_ptr<StreamTracker> streamTracker() override { return stream_tracker_; }
  ReverseTunnelStats& reverseTunnelStats() override { return reverse_tunnel_stats_; }

  std::shared_ptr<const envoy::config::core::v3::Address> chooseUpstreamAddress() override {
    auto addr = upstream_addresses_[round_robin_index_];
    round_robin_index_ = (round_robin_index_ + 1) % upstream_addresses_.size();
    return addr;
  }

private:
  ClusterInfoConstSharedPtr cluster_info_;
  std::shared_ptr<StreamTracker> stream_tracker_;
  std::vector<std::shared_ptr<const envoy::config::core::v3::Address>> upstream_addresses_;
  ReverseTunnelStats& reverse_tunnel_stats_; // owned by the cluster
  size_t round_robin_index_{0};
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
      reverse_tunnel_stat_names_(info_->statsScope().symbolTable()),
      reverse_tunnel_stats_(reverse_tunnel_stat_names_, info_->statsScope(), reverse_tunnel_stat_names_.reverse_tunnel_),
      dispatcher_(cluster_context.serverFactoryContext().mainThreadDispatcher()),
      owned_context_(std::make_unique<ReverseTunnelClusterContextImpl>(
        info_, stream_tracker_, load_assignment, reverse_tunnel_stats_)) {
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

  return update(cluster_load_assignment);
}

absl::Status SshReverseTunnelCluster::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                                                     const Protobuf::RepeatedPtrField<std::string>&,
                                                     const std::string&) {
  // On a delta xds update, rebuild using only the added resource. Same logic as the EDS cluster
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

  auto hostMap = priority_set_.crossPriorityHostMap();
  std::unordered_map<std::string, envoy::config::endpoint::v3::LbEndpoint> updatedEndpoints{};
  for (const auto& locality_lb_endpoint : cluster_load_assignment.endpoints()) {
    for (const auto& lb_endpoint : locality_lb_endpoint.lb_endpoints()) {
      updatedEndpoints.insert({lb_endpoint.endpoint().address().socket_address().address(), lb_endpoint});
    }
  }

  HostVector hostsToAdd;
  std::set<std::weak_ptr<Envoy::Upstream::Host>, std::owner_less<>> hostsToRemove;
  std::map<std::weak_ptr<Envoy::Upstream::Host>, std::shared_ptr<envoy::config::core::v3::Metadata>, std::owner_less<>> hostsToUpdate;
  for (const auto& [key, value] : *hostMap) {
    if (!updatedEndpoints.contains(key)) {
      hostsToRemove.insert(value);
    }
  }
  for (const auto& [endpointName, endpointData] : updatedEndpoints) {
    auto endpointNameView = std::string_view(endpointName);
    auto endpointMd = std::make_shared<envoy::config::core::v3::Metadata>(endpointData.metadata());
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

      hostsToAdd.push_back(InternalStreamHost::create(streamId, endpointMd, *owned_context_));
    } else {
      hostsToUpdate[hostMap->at(endpointNameView)] = endpointMd;
    }
  }

  auto filteredHostSetCopy = std::make_shared<HostVector>();
  // Add all the existing hosts, except those that have been removed
  for (auto& host : hostSet) {
    if (hostsToRemove.contains(host)) {
      // Note: when removing a host by passing it to updateHosts, the host object will be kept
      // alive until all its active connections (if any) have been closed.
      host->setEdsHealthStatus(envoy::config::core::v3::HealthStatus::DRAINING);
      continue;
    }
    if (hostsToUpdate.contains(host)) {
      // Update metadata for existing hosts if needed
      host->metadata(hostsToUpdate[host]);
    }
    filteredHostSetCopy->push_back(host);
  }
  // Add the new hosts
  filteredHostSetCopy->append_range(hostsToAdd);

  ENVOY_LOG(info, "updating endpoints for cluster {}: {} added, {} removed, {} total", edsServiceName(),
            hostsToAdd.size(), hostsToRemove.size(), filteredHostSetCopy->size());
  priority_set_.updateHosts(priority,
                            HostSetImpl::partitionHosts(filteredHostSetCopy, HostsPerLocalityImpl::empty()), {},
                            std::move(hostsToAdd),
                            HostVector{hostsToRemove.begin(), hostsToRemove.end()},
                            server_context_.api().randomGenerator().random());

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