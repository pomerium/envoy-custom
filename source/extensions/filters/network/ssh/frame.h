#pragma once

#include "source/extensions/filters/network/generic_proxy/interface/stream.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"

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
  SSHRequestHeaderFrame(AuthStateSharedPtr downstream_state);
  std::string_view host() const override;
  std::string_view protocol() const override;
  const AuthStateSharedPtr& authState() const;
  FrameFlags frameFlags() const override;
  FrameKind frameKind() const final;

private:
  AuthStateSharedPtr downstream_state_;
};

class SSHResponseCommonFrame : public GenericProxy::ResponseCommonFrame, public SSHStreamFrame {
  friend class SSHResponseHeaderFrame;

public:
  template <typename T>
  SSHResponseCommonFrame(uint64_t stream_id, T&& msg)
      : msg_(std::forward<T>(msg)),
        stream_id_(stream_id) {}

  template <typename T>
  SSHResponseCommonFrame(const SSHResponseCommonFrame& other)
      : msg_(other.msg_.message.get<T>()) {
  }

  FrameKind frameKind() const final;
  auto& message(this auto& self) { return self.msg_; }
  FrameFlags frameFlags() const override;

private:
  wire::Message msg_;
  uint64_t stream_id_;
};

class SSHResponseHeaderFrame : public GenericProxy::ResponseHeaderFrame, public SSHStreamFrame {
public:
  template <typename T>
  SSHResponseHeaderFrame(uint64_t stream_id, StreamStatus status, T&& msg)
      : status_(status),
        msg_(std::forward<T>(msg)),
        stream_id_(stream_id) {}

  static std::unique_ptr<SSHResponseHeaderFrame> sentinel(uint64_t stream_id) {
    return std::unique_ptr<SSHResponseHeaderFrame>{new SSHResponseHeaderFrame(stream_id)};
  }

  StreamStatus status() const override;
  std::string_view protocol() const override;
  FrameFlags frameFlags() const override;
  auto& message(this auto& self) { return self.msg_; }
  FrameKind frameKind() const final;
  uint64_t streamId() const;

  void setRawFlags(uint32_t raw_flags);
  void setStatus(StreamStatus status);
  bool isSentinel() const;

private:
  SSHResponseHeaderFrame(uint64_t stream_id);
  StreamStatus status_;
  wire::Message msg_;
  uint64_t stream_id_;
  std::optional<uint32_t> raw_flags_;
  bool is_sentinel_{false};
};

class SSHRequestCommonFrame : public GenericProxy::RequestCommonFrame, public SSHStreamFrame {
public:
  template <typename T>
  SSHRequestCommonFrame(uint64_t stream_id, T&& msg)
      : msg_(std::forward<T>(msg)),
        stream_id_(stream_id) {}
  FrameKind frameKind() const final;
  auto& message(this auto& self) { return self.msg_; }
  FrameFlags frameFlags() const override;
  uint64_t streamId() const;

private:
  wire::Message msg_;
  uint64_t stream_id_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec