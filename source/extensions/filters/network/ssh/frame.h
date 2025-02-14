#pragma once
#include "source/extensions/filters/network/generic_proxy/interface/stream.h"
#include "source/extensions/filters/network/ssh/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum class FrameKind {
  Unknown = 0,
  RequestHeader = 1,
  RequestCommon = 2,
  ResponseHeader = 3,
  ResponseCommon = 4,
};

class SSHStreamFrame {
public:
  virtual ~SSHStreamFrame() = default;
  virtual FrameKind frameKind() const PURE;
};

struct AuthState;
using AuthStateSharedPtr = std::shared_ptr<AuthState>;

class SSHRequestHeaderFrame : public GenericProxy::RequestHeaderFrame, public SSHStreamFrame {
public:
  SSHRequestHeaderFrame(AuthStateSharedPtr downstreamState);
  std::string_view host() const override;
  std::string_view protocol() const override;
  const AuthStateSharedPtr& authState() const;
  FrameFlags frameFlags() const override;

  FrameKind frameKind() const override;

private:
  AuthStateSharedPtr downstream_state_;
};

class SSHResponseHeaderFrame : public GenericProxy::ResponseHeaderFrame, public SSHStreamFrame {
public:
  template <typename T>
  SSHResponseHeaderFrame(uint64_t streamId, StreamStatus status, T&& msg)
      : status_(status), msg_(std::make_unique<T>(std::forward<T>(msg))), stream_id_(streamId) {}

  StreamStatus status() const override;
  std::string_view protocol() const override;
  FrameFlags frameFlags() const override;
  const SshMsg& message() const;
  FrameKind frameKind() const override;

  void setRawFlags(uint32_t raw_flags) { raw_flags_ = raw_flags; }
  void setStatus(StreamStatus status) { status_ = status; };

private:
  StreamStatus status_;
  std::unique_ptr<SshMsg> msg_;
  uint64_t stream_id_;
  std::optional<uint32_t> raw_flags_{};
};

class SSHRequestCommonFrame : public GenericProxy::RequestCommonFrame, public SSHStreamFrame {
public:
  template <typename T>
  SSHRequestCommonFrame(uint64_t streamId, T&& msg)
      : msg_(std::make_unique<T>(std::forward<T>(msg))), stream_id_(streamId) {}
  FrameKind frameKind() const override;
  const SshMsg& message() const;
  FrameFlags frameFlags() const override;

private:
  std::unique_ptr<SshMsg> msg_;
  uint64_t stream_id_;
};

class SSHResponseCommonFrame : public GenericProxy::ResponseCommonFrame, public SSHStreamFrame {
public:
  template <typename T>
  SSHResponseCommonFrame(uint64_t streamId, T&& msg)
      : msg_(std::make_unique<T>(std::forward<T>(msg))), stream_id_(streamId) {}
  FrameKind frameKind() const override;
  const SshMsg& message() const;
  FrameFlags frameFlags() const override;

private:
  std::unique_ptr<SshMsg> msg_;
  uint64_t stream_id_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec