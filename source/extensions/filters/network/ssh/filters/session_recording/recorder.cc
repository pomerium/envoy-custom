#include "source/extensions/filters/network/ssh/filters/session_recording/recorder.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/formatter_asciicast.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

SessionRecorder::SessionRecorder(std::shared_ptr<Config> config)
    : config_(config) {}

SessionRecorder::~SessionRecorder() {
  stopOnce();
}

void SessionRecorder::stopOnce() {
  if (!started_) {
    return;
  }
  if (!stopped_) {
    ENVOY_LOG(info, "session recording completed");
    stopped_ = true;
    formatter_ = nullptr;
    file_->close();
  }
}
absl::Status SessionRecorder::onStreamBegin(const Codec::SSHRequestHeaderFrame& frame, Filesystem::FilePtr file) {
  started_ = true;
  file_ = std::move(file);
  (void)frame;
  ENVOY_LOG(info, "session recording started (path={})", file_->path());

  auto fileOutput = std::make_unique<FileOutput>(*file_);
  formatter_.reset(new AsciicastFormatter(std::move(fileOutput)));

  if (frame.authState()->channel_mode == Codec::ChannelMode::Handoff) {
    // if the channel is in handoff mode, the client has already sent its pty info and it will
    // be available in the frame auth state
    formatter_->writeHeader(*frame.authState()->handoff_info.pty_info);
  }
  return absl::OkStatus();
}

void SessionRecorder::onStreamEnd(const Codec::SSHResponseHeaderFrame& frame) {
  (void)frame;
  stopOnce();
}

void SessionRecorder::handleDownstreamToUpstreamMessage(wire::Message& msg) {
  if (!isRecording()) {
    return;
  }
  msg.visit(
    [&](wire::ChannelRequestMsg& msg) {
      msg.msg.visit(
        [&](wire::PtyReqChannelRequestMsg& msg) {
          formatter_->writeHeader(msg);
        },
        [&](wire::WindowDimensionChangeChannelRequestMsg& msg) {
          formatter_->writeResizeEvent(msg);
        },
        [&](auto&) {});
    },
    [&](wire::ChannelDataMsg& msg) {
      formatter_->writeInputEvent(msg);
    },
    [&](auto&) {});
}

void SessionRecorder::handleUpstreamToDownstreamMessage(wire::Message& msg) {
  if (!isRecording()) {
    return;
  }
  msg.visit(
    [&](wire::ChannelDataMsg& msg) {
      formatter_->writeOutputEvent(msg);
    },
    [&](auto&) {});
}

bool SessionRecorder::isRecording() {
  return started_ && !stopped_;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording