#pragma once

#include "source/extensions/filters/network/ssh/filters/session_recording/formatter.h"
#include "source/common/json/json_streamer.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

template <OutputBufferType T>
class AsciicastFormatter : public OutputBufferFormatter<T> {
public:
  AsciicastFormatter(std::unique_ptr<T> output_buffer)
      : OutputBufferFormatter<T>(std::move(output_buffer)),
        streamer_(std::make_unique<Json::StreamerBase<T>>(this->output())) {}

  void writeHeader(const pomerium::extensions::ssh::SSHDownstreamPTYInfo& handoff_info) override {
    {
      auto header = streamer_->makeRootMap();
      header->addKey("version");
      header->addNumber(2ul);
      header->addKey("width");
      header->addNumber(static_cast<uint64_t>(handoff_info.width_columns()));
      header->addKey("height");
      header->addNumber(static_cast<uint64_t>(handoff_info.height_rows()));
      header->addKey("timestamp");
      header->addNumber(absl::ToUnixSeconds(this->startTime()));
      header->addKey("env");
      auto env = header->addMap();
      env->addKey("TERM");
      env->addString(handoff_info.term_env());
    }
    writeNewline();
  }

  void writeHeader(const wire::PtyReqChannelRequestMsg& msg) override {
    {
      auto header = streamer_->makeRootMap();
      header->addKey("version");
      header->addNumber(2ul);
      header->addKey("width");
      header->addNumber(static_cast<uint64_t>(msg.width_columns));
      header->addKey("height");
      header->addNumber(static_cast<uint64_t>(msg.height_rows));
      header->addKey("timestamp");
      header->addNumber(absl::ToUnixSeconds(this->startTime()));
      header->addKey("env");
      auto env = header->addMap();
      env->addKey("TERM");
      env->addString(*msg.term_env);
    }
    writeNewline();
  }

  void writeResizeEvent(const wire::WindowDimensionChangeChannelRequestMsg& msg) override {
    {
      auto arr = streamer_->makeRootArray();
      arr->addNumber(timeSinceStart());
      arr->addString("r");
      arr->addString(fmt::format("{}x{}", msg.width_columns, msg.height_rows));
    }
    writeNewline();
  }

  void writeOutputEvent(const wire::ChannelDataMsg& msg) override {
    {
      auto arr = streamer_->makeRootArray();
      arr->addNumber(timeSinceStart());
      arr->addString("o");

      auto rawData = std::string_view(reinterpret_cast<const char*>(msg.data->data()), msg.data->size());
      arr->addString(rawData);
    }
    writeNewline();
  }

  void writeInputEvent(const wire::ChannelDataMsg& msg) override {
    (void)msg;
  }

private:
  inline void writeNewline() { this->output().add("\n"); }

  double timeSinceStart() const {
    return absl::ToDoubleSeconds(absl::Now() - this->startTime());
  }

  std::unique_ptr<Json::StreamerBase<T>> streamer_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording