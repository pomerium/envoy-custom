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
    metadata_.set_format(formatter_->format());

    formatter_->flush();
    formatter_ = nullptr;
    file_->close();

    if (auto [ok, err] = file_->open(Filesystem::FlagSet{1 << Filesystem::File::Operation::Read}); err) {
      ENVOY_LOG(error, "failed to stat file {}: {}", file_->path(), err->getErrorDetails());
    }
    if (auto [info, err] = file_->info(); !err) {
      metadata_.set_recording_name(info.name_);
      metadata_.set_uncompressed_size(*info.size_);
    } else {
      ENVOY_LOG(error, "failed to stat file {}: {}", file_->path(), err->getErrorDetails());
    }
    file_->close();
    file_ = nullptr;

    *metadata_.mutable_start_time() = Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::ToUnixNanos(start_time_));
    *metadata_.mutable_end_time() = Protobuf::util::TimeUtil::NanosecondsToTimestamp(absl::ToUnixNanos(*end_time_));
    callbacks_.finalize(std::move(metadata_));
    metadata_.Clear();
  }
}

absl::Status SessionRecorder::onStreamBegin(
  const Codec::SSHRequestHeaderFrame& frame,
  Filesystem::FilePtr file,
  Format format,
  Envoy::Event::Dispatcher& dispatcher,
  std::string_view route_name) {
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
      std::make_unique<BufferedFileOutput>(*file_, dispatcher), start_time_, false);
    break;
  case Format::RawEncryptedFormat:
    formatter_ = std::make_unique<RawFormatter<BufferedFileOutput>>(
      std::make_unique<BufferedFileOutput>(*file_, dispatcher), start_time_, true);
    break;
  default:
    return absl::InvalidArgumentError(fmt::format("unknown format: {}", static_cast<int>(format)));
  }

  metadata_.Clear();
  if (frame.authState()->allow_response != nullptr) {
    const auto& allowResp = frame.authState()->allow_response;
    metadata_.set_login_name(allowResp->username());
    if (allowResp->has_upstream()) {
      metadata_.mutable_upstream()->CopyFrom(allowResp->upstream());
      metadata_.set_stream_id(frame.authState()->stream_id);
      metadata_.set_route_name(route_name);
    }
  }
  if (frame.authState()->channel_mode == Codec::ChannelMode::Handoff) {
    // if the channel is in handoff mode, the client has already sent its pty info and it will
    // be available in the frame auth state (unless the channel is direct-tcpip)
    if (frame.authState()->handoff_info.pty_info) {
      metadata_.mutable_pty_info()->CopyFrom(*frame.authState()->handoff_info.pty_info);
    } else {
      metadata_.mutable_pty_info()->Clear();
    }
    formatter_->writeHeader(metadata_.pty_info());
    wrote_header_ = true;
  }
  return absl::OkStatus();
}

void SessionRecorder::onStreamEnd(const Codec::SSHResponseHeaderFrame& frame) {
  if (!isRecording() || !wrote_header_) {
    return;
  }
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
      msg.request.visit(
        [&](wire::PtyReqChannelRequestMsg& msg) {
          // TODO: deduplicate this message conversion
          formatter_->writeHeader(msg);
          wrote_header_ = true;
          if (!metadata_.has_pty_info()) {
            SSHDownstreamPTYInfo pty_info;
            *pty_info.mutable_term_env() = msg.term_env;
            pty_info.set_width_columns(msg.width_columns);
            pty_info.set_height_rows(msg.height_rows);
            pty_info.set_width_columns(msg.width_columns);
            pty_info.set_width_px(msg.width_px);
            *pty_info.mutable_modes() = msg.modes;
            *metadata_.mutable_pty_info() = pty_info;
          }
        },
        [&](wire::WindowDimensionChangeChannelRequestMsg& msg) {
          if (!wrote_header_) {
            return;
          }
          formatter_->writeResizeEvent(msg);
        },
        [&](auto&) {});
    },
    [&](wire::ChannelDataMsg& msg) {
      if (!wrote_header_) {
        return;
      }
      formatter_->writeInputEvent(msg);
    },
    [&](auto&) {});
}

void SessionRecorder::handleUpstreamToDownstreamMessage(wire::Message& msg) {
  if (!isRecording() || !wrote_header_) {
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