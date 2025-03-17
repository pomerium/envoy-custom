#pragma once

#include <memory>

#include "envoy/thread_local/thread_local.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/shared.h"
#include "source/extensions/filters/network/ssh/vt_buffer.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using ::Envoy::Event::Dispatcher;

// Upstream
class SourceUpstreamSessionMultiplexer : public SourceCallbacks,
                                         public std::enable_shared_from_this<SourceUpstreamSessionMultiplexer>,
                                         public virtual Logger::Loggable<Logger::Id::filter> {
public:
  SourceUpstreamSessionMultiplexer(
    Api::Api& api,
    TransportCallbacks& transport,
    std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> tls,
    Dispatcher& dispatcher)
      : api_(api),
        transport_(transport),
        tls_(tls),
        local_dispatcher_(dispatcher),
        vt_state_(std::make_shared<VTCurrentStateTracker>()) {
    (void)api_;
  }

  void onStreamBegin(const AuthState& auth_state) {
    info_ = auth_state.multiplexing_info;

    current_stream_id_ = auth_state.stream_id;

    ENVOY_LOG(debug, "new multiplex source: {}", auth_state.stream_id);
    (*tls_)->beginSession(auth_state.stream_id, weak_from_this());
    if (auth_state.channel_mode == ChannelMode::Handoff && auth_state.handoff_info.pty_info) {
      vt_state_->resize(static_cast<int>(auth_state.handoff_info.pty_info->width_columns()),
                        static_cast<int>(auth_state.handoff_info.pty_info->height_rows()));
      // TODO: do something with term_env/modes?
    }
  }

  void onStreamEnd() {
    if (!stream_ending_ && current_stream_id_.has_value()) {
      stream_ending_ = true;
      if (auto r = (*tls_)->shutdownSession(current_stream_id_.value()); !r.ok()) {
        ENVOY_LOG(error, "error shutting down session: {}", r.message());
      }
    }
  }

  absl::Status handleUpstreamToDownstreamMessage(wire::Message& msg) {
    ASSERT(info_.multiplex_mode == Codec::MultiplexMode::Source);

    msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        updateSource(msg);
      },
      [](const auto&) {});
    return absl::OkStatus();
  }

  void updateSource(const wire::ChannelDataMsg& msg) {
    vt_state_->write(msg.data);
    for (auto&& it = active_mirrors_.begin(); it != active_mirrors_.end();) {
      if (auto s = it->lock(); s) {
        s->sendMsg(msg);
        it++;
      } else {
        it = active_mirrors_.erase(it);
      }
    }
  }

  void onMirrorAdded(std::weak_ptr<MirrorCallbacks> mc) override {
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this, mc = mc] { onMirrorAdded(mc); });
      return;
    }
    active_mirrors_.insert(mc);
    if (auto l = mc.lock(); l) {
      l->onSourceResized(vt_state_->width(), vt_state_->height());
      Envoy::Buffer::OwnedImpl buffer;
      vt_state_->dumpState(buffer);
      wire::ChannelDataMsg state;
      state.data = wire::flushTo<bytes>(buffer);
      l->sendMsg(state);
    }
  }

  void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) override {
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this, mc = mc] { onMirrorRemoved(mc); });
      return;
    }
    active_mirrors_.erase(mc);
    if (stream_ending_ && active_mirrors_.empty()) {
      (*tls_)->endSession(*current_stream_id_);
      current_stream_id_.reset();
    }
  }

  // SourceInterface
  void inject(const wire::ChannelDataMsg& msg) override {
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this, msg = msg] { inject(msg); });
      return;
    }
    auto r = transport_.sendMessageToConnection(msg);
    if (!r.ok()) {
      ENVOY_LOG(error, "error sending message: {}", r.status().message());
    }
  }
  void resize(const wire::WindowDimensionChangeChannelRequestMsg& msg) override {
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this, msg = msg] { resize(msg); });
      return;
    }
    vt_state_->resize(static_cast<int>(*msg.width_columns), static_cast<int>(*msg.height_rows));
  }

private:
  Api::Api& api_;
  TransportCallbacks& transport_;

  Codec::MultiplexingInfo info_;
  std::optional<uint64_t> current_stream_id_;
  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> tls_;
  Dispatcher& local_dispatcher_;
  bool stream_ending_{false};
  std::set<std::weak_ptr<MirrorCallbacks>, std::owner_less<>> active_mirrors_;
  std::shared_ptr<VTCurrentStateTracker> vt_state_;
};

class SourceDownstreamSessionMultiplexer : public SourceInterfaceCallbacks {
public:
  void onStreamEnd() {
    if (!stream_ending_) {
      stream_ending_ = true;
    }
  }
  void setSourceInterface(std::weak_ptr<SourceInterface> si) override {
    source_interface_ = std::move(si);
  }
  absl::Status handleDownstreamToUpstreamMessage(wire::Message& msg) {
    if (stream_ending_ || !source_interface_.has_value()) {
      return absl::OkStatus();
    }
    return msg.visit(
      [&](const wire::ChannelRequestMsg& channel_req) {
        return channel_req.msg.visit(
          [&](const wire::WindowDimensionChangeChannelRequestMsg& msg) {
            if (auto l = (*source_interface_).lock(); l) {
              l->resize(msg);
            }
            return absl::OkStatus();
          },
          [](auto&) {
            return absl::OkStatus();
          });
      },
      [](auto&) {
        return absl::OkStatus();
      });
  }

private:
  std::optional<std::weak_ptr<SourceInterface>> source_interface_;
  bool stream_ending_{false};
};

// Downstream
class MirrorSessionMultiplexer : public MirrorCallbacks,
                                 public VTBufferCallbacks,
                                 public std::enable_shared_from_this<MirrorSessionMultiplexer>,
                                 public virtual Logger::Loggable<Logger::Id::filter> {
public:
  MirrorSessionMultiplexer(
    Api::Api& api,
    TransportCallbacks& transport,
    std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> tls,
    Dispatcher& dispatcher)
      : api_(api),
        transport_(transport),
        tls_(tls),
        local_dispatcher_(dispatcher),
        vt_(std::make_unique<VTBuffer>(*this)) {
    (void)api_;
  }

  void onStreamBegin(const AuthState& auth_state) {
    info_ = auth_state.multiplexing_info;
    switch (info_.multiplex_mode) {
    case Codec::MultiplexMode::Mirror:
      ENVOY_LOG(debug, "new multiplex mirror: {}", info_.source_stream_id);
      // NB: session is attached later, after channel is opened
      current_stream_id_ = auth_state.multiplexing_info.source_stream_id;

      if (info_.downstream_channel_id.has_value()) {
        sender_channel_ = info_.downstream_channel_id;

        auto r = (*tls_)->attachToSession(info_.source_stream_id, weak_from_this());
        if (!r.ok()) {
          wire::DisconnectMsg dc;
          dc.reason_code = SSH2_DISCONNECT_BY_APPLICATION;
          dc.description = std::string(r.status().message());
          if (auto r = transport_.sendMessageToConnection(dc); !r.ok()) {
            ENVOY_LOG(error, "error sending disconnect message: {}", r.status().message());
          }
          ENVOY_LOG(error, "attaching to session failed: {}", r.status());
          return;
        }
        source_interface_ = *r;
        if (source_interface_.expired()) {
          wire::DisconnectMsg dc;
          dc.reason_code = SSH2_DISCONNECT_BY_APPLICATION;
          dc.description = "session ended";
          if (auto r = transport_.sendMessageToConnection(dc); !r.ok()) {
            ENVOY_LOG(error, "error sending disconnect message: {}", r.status().message());
          }
          ENVOY_LOG(error, "attaching to session failed: session ended");
          return;
        } else {
          ENVOY_LOG(debug, "attaching to session succeeded");
        }
      }
      break;
    default:
      PANIC("unknown mode");
    }
  }

  absl::Status handleDownstreamToUpstreamMessage(wire::Message& msg) {
    if (stream_ending_) {
      return absl::OkStatus();
    }
    return msg.visit(
      [&](const wire::ChannelOpenMsg& msg) {
        sender_channel_ = msg.sender_channel;
        wire::ChannelOpenConfirmationMsg confirm;
        confirm.sender_channel = 1;
        confirm.recipient_channel = *sender_channel_;
        confirm.initial_window_size = msg.initial_window_size;
        confirm.max_packet_size = msg.max_packet_size;
        return transport_.sendMessageToConnection(confirm).status();
      },
      [&](const wire::ChannelRequestMsg& channel_req) {
        if (!sender_channel_.has_value()) {
          return absl::OkStatus();
        }
        return channel_req.msg.visit(
          [&](const wire::PtyReqChannelRequestMsg&) {
            wire::ChannelSuccessMsg success;
            success.recipient_channel = *sender_channel_;
            return transport_.sendMessageToConnection(success).status();
          },
          [&](const wire::ShellChannelRequestMsg&) {
            ENVOY_LOG(debug, "attaching mirror to session: {}", info_.source_stream_id);
            wire::ChannelSuccessMsg success;
            success.recipient_channel = *sender_channel_;
            if (auto r = transport_.sendMessageToConnection(success); !r.ok()) {
              ENVOY_LOG(error, "attaching to session failed: error responding to client request: {}", r.status().message());
              return r.status();
            }

            auto r = (*tls_)->attachToSession(info_.source_stream_id, weak_from_this());
            if (!r.ok()) {
              ENVOY_LOG(error, "attaching to session failed: {}", r.status());
              return r.status();
            }
            source_interface_ = *r;
            if (source_interface_.expired()) {
              ENVOY_LOG(error, "attaching to session failed");
              return absl::InvalidArgumentError("attaching to session failed");
            } else {
              ENVOY_LOG(debug, "attaching to session succeeded");
            }
            return absl::OkStatus();
          },
          [](const auto&) {
            return absl::OkStatus();
          });
      },
      [&](const wire::ChannelDataMsg& msg) {
        if (auto l = source_interface_.lock(); l) {
          l->inject(msg);
        }
        return absl::OkStatus();
      },
      [](const auto&) {
        return absl::OkStatus();
      });
  }

  // MirrorCallbacks
  void sendMsg(const wire::Message& msg) override {
    if (stream_ending_) {
      return;
    }
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this, msg = msg]() { sendMsg(msg); });
      return;
    }
    bool send = msg.visit(
      // [&](const wire::ChannelDataMsg& msg) {
      //   vt_->write(msg.data);
      //   return false;
      // },
      [&](wire::ChannelMsg auto& msg) {
        // inject the downstream channel ID
        msg.recipient_channel = *sender_channel_;
        return true;
      },
      [](auto&) { return true; });
    if (!send) {
      return;
    }
    auto r = transport_.sendMessageToConnection(msg);
    if (!r.ok()) {
      ENVOY_LOG(error, "error sending message: {}", r.status().message());
    }
  }
  void onUpdate(Envoy::Buffer::Instance& buf) override {
    if (stream_ending_ || !sender_channel_.has_value()) {
      return;
    }
    wire::ChannelDataMsg msg;
    msg.data = wire::flushTo<bytes>(buf);
    msg.recipient_channel = *sender_channel_;
    auto r = transport_.sendMessageToConnection(msg);
    if (!r.ok()) {
      ENVOY_LOG(error, "error sending message: {}", r.status().message());
    }
  }
  void onSourceResized(int width, int height) override {
    if (stream_ending_) {
      return;
    }
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this, width, height]() { onSourceResized(width, height); });
      return;
    }
    vt_->resize(width, height);
  }
  void onStreamEnd() override {
    if (!local_dispatcher_.isThreadSafe()) {
      local_dispatcher_.post([this] { onStreamEnd(); });
      return;
    }
    if (!stream_ending_ && current_stream_id_.has_value()) {
      stream_ending_ = true;
      auto stat = (*tls_)->detachFromSession(*current_stream_id_, shared_from_this());
      if (!stat.ok()) {
        ENVOY_LOG(error, stat.message());
        // keep going
      }
      current_stream_id_.reset();
      source_interface_.reset();
      wire::DisconnectMsg dc;
      dc.reason_code = SSH2_DISCONNECT_BY_APPLICATION;
      dc.description = "session ended";
      if (auto r = transport_.sendMessageToConnection(dc); !r.ok()) {
        ENVOY_LOG(error, "error sending disconnect message: {}", r.status().message());
      }
    }
  }

private:
  Api::Api& api_;
  TransportCallbacks& transport_;
  bool stream_ending_{false};

  Codec::MultiplexingInfo info_;
  std::optional<uint64_t> current_stream_id_;
  std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> tls_;
  Dispatcher& local_dispatcher_;
  std::weak_ptr<SourceInterface> source_interface_;
  std::optional<uint32_t> sender_channel_;
  std::unique_ptr<VTBuffer> vt_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec