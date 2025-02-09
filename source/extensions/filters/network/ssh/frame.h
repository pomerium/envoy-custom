#pragma once
#include "source/extensions/filters/network/generic_proxy/interface/stream.h"
#include "source/extensions/filters/network/ssh/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum class FrameKind {
  Unknown = 0,
  RequestHeader = 1,
  ResponseHeader = 2,
};

class SSHStreamFrame {
public:
  virtual ~SSHStreamFrame() = default;
  virtual FrameKind frameKind() const PURE;
};

class SSHRequestHeaderFrame : public GenericProxy::RequestHeaderFrame, public SSHStreamFrame {
public:
  SSHRequestHeaderFrame(std::string_view username, std::string_view host,
                        std::string_view our_version)
      : username_(username), host_(host), our_version_(our_version) {}
  std::string_view host() const override { return host_; };
  std::string_view protocol() const override { return "ssh"; };
  std::string_view ourVersion() const { return our_version_; };

  FrameKind frameKind() const override { return FrameKind::RequestHeader; };

private:
  std::string username_;
  std::string host_;
  std::string our_version_;
};

class SSHResponseHeaderFrame : public GenericProxy::ResponseHeaderFrame, public SSHStreamFrame {
public:
  template <typename T>
  SSHResponseHeaderFrame(StreamStatus status, T&& msg)
      : status_(status), msg_(std::make_unique<T>(std::forward<T>(msg))) {}
  StreamStatus status() const override { return status_; }
  std::string_view protocol() const override { return "ssh"; };

  FrameFlags frameFlags() const override { return {}; }

  const SshMsg& message() const { return *msg_; }

  FrameKind frameKind() const override { return FrameKind::ResponseHeader; };

private:
  StreamStatus status_;
  std::unique_ptr<SshMsg> msg_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec