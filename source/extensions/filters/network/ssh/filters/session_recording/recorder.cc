#include "source/extensions/filters/network/ssh/filters/session_recording/recorder.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/formatter_asciicast.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/formatter_raw.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

SessionRecorder::SessionRecorder(std::shared_ptr<Config> config, SessionRecordingCallbacks& callbacks)
    : config_(config),
      callbacks_(callbacks) {}

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
    if (!end_time_.has_value()) {
      end_time_ = absl::Now();
    }
    RecordingMetadata md;
    md.set_format(formatter_->format());

    formatter_->flush();
    formatter_ = nullptr;
    file_->close();

    if (auto [ok, err] = file_->open(Filesystem::FlagSet{1 << Filesystem::File::Operation::Read}); err) {
      ENVOY_LOG(error, "failed to stat file {}: {}", file_->path(), err->getErrorDetails());
    }
    if (auto [info, err] = file_->info(); !err) {
      md.set_recording_name(info.name_);
      md.set_uncompressed_size(*info.size_);
    } else {
      ENVOY_LOG(error, "failed to stat file {}: {}", file_->path(), err->getErrorDetails());
    }
    file_->close();
    file_ = nullptr;

    *md.mutable_start_time() = Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::ToUnixNanos(start_time_));
    *md.mutable_end_time() = Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::ToUnixNanos(*end_time_));
    callbacks_.finalize(std::move(md));
  }
}

absl::Status SessionRecorder::onStreamBegin(
  const Codec::SSHRequestHeaderFrame& frame,
  Filesystem::FilePtr file,
  Format format,
  Envoy::Event::Dispatcher& dispatcher) {
  started_ = true;
  start_time_ = absl::Now();
  file_ = std::move(file);
  ENVOY_LOG(info, "session recording started (path={})", file_->path());

  switch (format) {
  case Format::AsciicastFormat:
    formatter_ = std::make_unique<AsciicastFormatter<BufferedFileOutput>>(
      std::make_unique<BufferedFileOutput>(*file_, dispatcher), start_time_);
    break;
  case Format::RawFormat:
    formatter_ = std::make_unique<RawFormatter<BufferedFileOutput>>(
      std::make_unique<BufferedFileOutput>(*file_, dispatcher), start_time_);
    break;
  default:
    return absl::InvalidArgumentError(fmt::format("unknown format: {}", static_cast<int>(format)));
  }

  if (frame.authState()->channel_mode == Codec::ChannelMode::Handoff) {
    // if the channel is in handoff mode, the client has already sent its pty info and it will
    // be available in the frame auth state
    formatter_->writeHeader(*frame.authState()->handoff_info.pty_info);
  }
  return absl::OkStatus();
}

void SessionRecorder::onStreamEnd(const Codec::SSHResponseHeaderFrame& frame) {
  end_time_ = absl::Now();
  formatter_->writeTrailer(frame.message(), *end_time_);
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