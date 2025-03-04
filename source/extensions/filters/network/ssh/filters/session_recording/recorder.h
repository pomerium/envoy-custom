#pragma once

#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/common/json/json_streamer.h"
#include "source/common/common/json_escape_string.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;

class FileOutput {
public:
  explicit FileOutput(Filesystem::File& file)
      : file_(file) {}
  void add(std::string_view a) {
    file_.write(a);
  }
  void add(std::string_view a, std::string_view b, std::string_view c) {
    file_.write(a);
    file_.write(b);
    file_.write(c);
  }

  Filesystem::File& file_;
};

class SessionRecorder : Logger::Loggable<Logger::Id::filter> {
public:
  SessionRecorder(std::shared_ptr<Config> config)
      : config_(config) {}

  ~SessionRecorder() {
    stopOnce();
  }

  void stopOnce() {
    if (!started_) {
      return;
    }
    if (!stopped_) {
      ENVOY_LOG(info, "session recording completed");
      stopped_ = true;
      streamer_ = nullptr;
      output_ = nullptr;
      file_->close();
    }
  }

  absl::Status onStreamBegin(const Codec::SSHRequestHeaderFrame& frame, Filesystem::FilePtr file) {
    started_ = true;
    start_time_ = absl::Now();
    file_ = std::move(file);
    (void)frame;
    ENVOY_LOG(info, "session recording started (path={})", file_->path());

    output_ = std::make_unique<FileOutput>(*file_);
    streamer_ = std::make_unique<Json::StreamerBase<FileOutput>>(*output_);

    if (frame.authState()->channel_mode == Codec::ChannelMode::Handoff) {
      // if the channel is in handoff mode, the client has already sent its pty info and it will
      // be available in the frame auth state
      writeHeader(*frame.authState()->handoff_info.pty_info);
    }
    return absl::OkStatus();
  }
  void onStreamEnd(const Codec::SSHResponseHeaderFrame& frame) {
    (void)frame;
    stopOnce();
  }
  void handleDownstreamToUpstreamMessage(const wire::Message& msg) {
    msg.visit(
      [&](const wire::ChannelRequestMsg& msg) {
        msg.msg.visit(
          [&](const wire::PtyReqChannelRequestMsg& msg) {
            writeHeader(msg);
          },
          [&](const wire::WindowDimensionChangeChannelRequestMsg& msg) {
            writeResizeEvent(msg);
          },
          [&](const auto&) {});
      },
      [&](const wire::ChannelDataMsg& msg) {
        writeInputEvent(msg);
      },
      [&](const auto&) {});
  }
  void handleUpstreamToDownstreamMessage(const wire::Message& msg) {
    msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        writeOutputEvent(msg);
      },
      [&](const auto&) {});
  }

private:
  void writeHeader(const pomerium::extensions::ssh::SSHDownstreamPTYInfo& handoff_info) {
    if (!isRecording()) {
      return;
    }
    {
      auto header = streamer_->makeRootMap();
      header->addKey("version");
      header->addNumber(2ul);
      header->addKey("width");
      header->addNumber(static_cast<uint64_t>(handoff_info.width_columns()));
      header->addKey("height");
      header->addNumber(static_cast<uint64_t>(handoff_info.height_rows()));
      header->addKey("timestamp");
      header->addNumber(absl::ToUnixSeconds(start_time_));
      header->addKey("env");
      auto env = header->addMap();
      env->addKey("TERM");
      env->addString(handoff_info.term_env());
    }
    output_->add("\n");
  }

  void writeHeader(const wire::PtyReqChannelRequestMsg& msg) {
    if (!isRecording()) {
      return;
    }
    {
      auto header = streamer_->makeRootMap();
      header->addKey("version");
      header->addNumber(2ul);
      header->addKey("width");
      header->addNumber(static_cast<uint64_t>(msg.width_columns));
      header->addKey("height");
      header->addNumber(static_cast<uint64_t>(msg.height_rows));
      header->addKey("timestamp");
      header->addNumber(absl::ToUnixSeconds(start_time_));
      header->addKey("env");
      auto env = header->addMap();
      env->addKey("TERM");
      env->addString(*msg.term_env);
    }
    output_->add("\n");
  }
  void writeResizeEvent(const wire::WindowDimensionChangeChannelRequestMsg& msg) {
    if (!isRecording()) {
      return;
    }
    {
      auto arr = streamer_->makeRootArray();
      arr->addNumber(timeSinceStart());
      arr->addString("r");
      arr->addString(fmt::format("{}x{}", msg.width_columns, msg.height_rows));
    }
    output_->add("\n");
  }
  void writeOutputEvent(const wire::ChannelDataMsg& msg) {
    if (!isRecording()) {
      return;
    }
    {
      auto arr = streamer_->makeRootArray();
      arr->addNumber(timeSinceStart());
      arr->addString("o");

      auto rawData = std::string_view(reinterpret_cast<const char*>(msg.data->data()), msg.data->size());
      arr->addString(rawData);
    }
    output_->add("\n");
  }
  void writeInputEvent(const wire::ChannelDataMsg& msg) {
    if (!isRecording()) {
      return;
    }
    // auto arr = streamer_->makeRootArray();
    // arr->addNumber(timeSinceStart());
    // arr->addString("i");
    // arr->addString(*msg.data);
    (void)msg;
  }
  double timeSinceStart() {
    return absl::ToDoubleSeconds(absl::Now() - start_time_);
  }
  bool isRecording() {
    return started_ && !stopped_;
  }
  bool started_{};
  bool stopped_{};
  absl::Time start_time_;
  Filesystem::FilePtr file_;
  std::unique_ptr<FileOutput> output_;
  std::unique_ptr<Json::StreamerBase<FileOutput>> streamer_;
  std::shared_ptr<Config> config_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording
