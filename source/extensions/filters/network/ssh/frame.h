#pragma once
#include "source/extensions/filters/network/generic_proxy/interface/stream.h"
#include "source/extensions/filters/network/ssh/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SSHRequestHeaderFrame : public GenericProxy::RequestHeaderFrame {
public:
  SSHRequestHeaderFrame(std::string_view host) : host_(host) {}
  std::string_view host() const override { return host_; };
  std::string_view protocol() const override { return "ssh"; };

private:
  std::string host_;
};

class ResponseHeaderFrame : public GenericProxy::ResponseHeaderFrame {
public:
  template <typename T>
  ResponseHeaderFrame(StreamStatus status, T&& msg)
      : status_(status), msg_(std::make_unique<T>(std::forward<T>(msg))) {}
  StreamStatus status() const override { return status_; }
  std::string_view protocol() const override { return "ssh"; };

  FrameFlags frameFlags() const override { return {}; }

  const SshMsg& message() const { return *msg_; }

private:
  StreamStatus status_;
  std::unique_ptr<SshMsg> msg_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec