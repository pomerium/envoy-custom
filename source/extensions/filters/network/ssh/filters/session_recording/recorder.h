#pragma once

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/formatter.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;

class SessionRecorder : Logger::Loggable<Logger::Id::filter> {
public:
  explicit SessionRecorder(std::shared_ptr<Config> config);
  ~SessionRecorder();

  absl::Status onStreamBegin(const Codec::SSHRequestHeaderFrame& frame, Filesystem::FilePtr file);
  void onStreamEnd(const Codec::SSHResponseHeaderFrame& frame);
  void handleDownstreamToUpstreamMessage(const wire::Message& msg);
  void handleUpstreamToDownstreamMessage(const wire::Message& msg);

private:
  void stopOnce();
  bool isRecording();

  bool started_{};
  bool stopped_{};
  Filesystem::FilePtr file_;
  std::unique_ptr<Formatter> formatter_;
  std::shared_ptr<Config> config_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording
