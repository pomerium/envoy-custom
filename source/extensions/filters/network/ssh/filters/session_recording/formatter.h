#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "envoy/filesystem/filesystem.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

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

private:
  Filesystem::File& file_;
};

class Formatter {
public:
  virtual ~Formatter() = default;
  virtual void writeHeader(const pomerium::extensions::ssh::SSHDownstreamPTYInfo& handoff_info) PURE;
  virtual void writeHeader(const wire::PtyReqChannelRequestMsg& msg) PURE;
  virtual void writeResizeEvent(const wire::WindowDimensionChangeChannelRequestMsg& msg) PURE;
  virtual void writeOutputEvent(const wire::ChannelDataMsg& msg) PURE;
  virtual void writeInputEvent(const wire::ChannelDataMsg& msg) PURE;
};

// this is a formal definition of the 'OutputBufferType' type parameter of Envoy::Json::StreamerBase
template <typename T>
concept OutputBufferType = requires(T t) {
  { t.add(std::string_view{}) };
  { t.add(std::string_view{}, std::string_view{}, std::string_view{}) };
};

template <OutputBufferType T>
class OutputBufferFormatter : public Formatter {
public:
  OutputBufferFormatter(std::unique_ptr<T> output)
      : output_(std::move(output)) {}

protected:
  inline T& output() { return *output_; }
  inline absl::Time startTime() const { return start_time_; }

private:
  std::unique_ptr<T> output_;
  absl::Time start_time_{absl::Now()};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording