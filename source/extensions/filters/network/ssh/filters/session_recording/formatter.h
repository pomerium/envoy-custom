#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/filesystem/filesystem.h"
#include "source/common/buffer/watermark_buffer.h"
#include "envoy/event/dispatcher.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Format;

static constexpr auto flush_interval = std::chrono::milliseconds(1000);
static constexpr auto buffer_high_watermark = 4 * 1024;

class BufferedFileOutput {
public:
  BufferedFileOutput(Filesystem::File& file, Envoy::Event::Dispatcher& dispatcher)
      : file_(file),
        flush_timer_(dispatcher.createTimer([this] { this->flush(); })),
        buffer_([] {}, [this] { this->flushBuffer(); }, [] {}),
        dispatcher_(dispatcher) {
    buffer_.setWatermarks(buffer_high_watermark);
    flush_timer_->enableTimer(flush_interval);
    ASSERT(dispatcher.isThreadSafe());
  }

  void add(std::string_view a) {
    buffer_.add(a);
  }

  void add(bytes_view a) {
    buffer_.add(a.data(), a.size());
  }

  void add(std::string_view a, std::string_view b, std::string_view c) {
    buffer_.addFragments({a, b, c});
  }

  void flush() {
    ASSERT(dispatcher_.isThreadSafe());
    flushBuffer();
  }

private:
  void flushBuffer() {
    flush_timer_->disableTimer();
    do {
      auto len = buffer_.length();
      char* slice = static_cast<char*>(buffer_.linearize(len));
      file_.write(std::string_view{unsafe_forge_span(slice, len)});
      buffer_.drain(len);
    } while (buffer_.highWatermarkTriggered());
    flush_timer_->enableTimer(flush_interval);
  }

  Thread::MutexBasicLockable watermark_mu_;
  Filesystem::File& file_;
  Envoy::Event::TimerPtr flush_timer_;
  Envoy::Buffer::WatermarkBuffer buffer_;
  Envoy::Event::Dispatcher& dispatcher_;
};

class Formatter {
public:
  virtual ~Formatter() = default;
  virtual constexpr Format format() const PURE;
  virtual void writeHeader(const pomerium::extensions::ssh::SSHDownstreamPTYInfo& handoff_info) PURE;
  virtual void writeHeader(const wire::PtyReqChannelRequestMsg& msg) PURE;
  virtual void writeTrailer(const wire::Message& /*msg*/, absl::Time /*end_time*/) {}
  virtual void writeResizeEvent(const wire::WindowDimensionChangeChannelRequestMsg& msg) PURE;
  virtual void writeOutputEvent(const wire::ChannelDataMsg& msg) PURE;
  virtual void writeInputEvent(const wire::ChannelDataMsg& msg) PURE;
  virtual void flush() PURE;
};

// this is a formal definition of the 'OutputBufferType' type parameter of Envoy::Json::StreamerBase
template <typename T>
concept OutputBufferType = requires(T t) {
  // envoy requirements
  { t.add(std::string_view{}) };
  { t.add(std::string_view{}, std::string_view{}, std::string_view{}) };
  // additional requirements
  { t.add(bytes_view{}) };
  { t.flush() };
};

template <OutputBufferType T>
class OutputBufferFormatter : public Formatter {
public:
  OutputBufferFormatter(std::unique_ptr<T> output, absl::Time start_time)
      : output_(std::move(output)), start_time_(start_time) {}

  void flush() final {
    output_->flush();
  }

protected:
  inline T& output() { return *output_; }
  inline absl::Time startTime() const { return start_time_; }

private:
  std::unique_ptr<T> output_;
  absl::Time start_time_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording