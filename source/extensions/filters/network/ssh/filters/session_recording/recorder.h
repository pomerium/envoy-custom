#pragma once

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/formatter.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;
using pomerium::extensions::ssh::filters::session_recording::Format;
using pomerium::extensions::ssh::filters::session_recording::RecordingMetadata;

class SessionRecordingCallbacks {
public:
  virtual ~SessionRecordingCallbacks() = default;
  virtual void finalize(RecordingMetadata) PURE;
};

class SessionRecorder : Logger::Loggable<Logger::Id::filter> {
public:
  explicit SessionRecorder(std::shared_ptr<Config> config, SessionRecordingCallbacks& callbacks);
  ~SessionRecorder();

  absl::Status onStreamBegin(
    const Codec::SSHRequestHeaderFrame& frame,
    Filesystem::FilePtr file,
    Format format,
    Envoy::Event::Dispatcher& dispatcher,
    std::string_view route_name);
  void onStreamEnd(const Codec::SSHResponseHeaderFrame& frame);
  void handleDownstreamToUpstreamMessage(wire::Message& msg);
  void handleUpstreamToDownstreamMessage(wire::Message& msg);

private:
  void stopOnce();
  bool isRecording();

  std::shared_ptr<Config> config_;
  SessionRecordingCallbacks& callbacks_;
  bool started_{};
  bool wrote_header_{};
  bool stopped_{};
  absl::Time start_time_;
  std::optional<absl::Time> end_time_;
  Filesystem::FilePtr file_;
  std::unique_ptr<Formatter> formatter_;
  RecordingMetadata metadata_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording
