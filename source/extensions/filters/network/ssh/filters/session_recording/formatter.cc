#include "source/extensions/filters/network/ssh/filters/session_recording/formatter.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

BufferedFileOutput::BufferedFileOutput(Filesystem::File& file, Envoy::Event::Dispatcher& dispatcher)
    : file_(file),
      flush_timer_(dispatcher.createTimer([this] { this->flush(); })),
      buffer_([] {}, [this] { this->flushBuffer(); }, [] {}),
      dispatcher_(dispatcher) {
  buffer_.setWatermarks(buffer_high_watermark);
  flush_timer_->enableTimer(flush_interval);
  ASSERT(dispatcher.isThreadSafe());
}

void BufferedFileOutput::add(std::string_view a) {
  buffer_.add(a);
}

void BufferedFileOutput::add(bytes_view a) {
  buffer_.add(a.data(), a.size());
}

void BufferedFileOutput::add(std::string_view a, std::string_view b, std::string_view c) {
  buffer_.addFragments({a, b, c});
}

void BufferedFileOutput::flush() {
  ASSERT(dispatcher_.isThreadSafe());
  flushBuffer();
}

void BufferedFileOutput::flushBuffer() {
  flush_timer_->disableTimer();
  do {
    auto len = buffer_.length();
    char* slice = static_cast<char*>(buffer_.linearize(static_cast<uint32_t>(len)));
    file_.write(std::string_view{unsafe_forge_span(slice, len)});
    buffer_.drain(len);
  } while (buffer_.highWatermarkTriggered());
  flush_timer_->enableTimer(flush_interval);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording