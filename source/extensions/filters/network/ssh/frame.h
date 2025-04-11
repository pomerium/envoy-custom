#pragma once

#include "source/extensions/filters/network/generic_proxy/interface/stream.h"

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using frame_tags_type = decltype(std::declval<GenericProxy::FrameFlags>().frameTags());

enum FrameTags : frame_tags_type {
  RequestCommon = 0b00,
  ResponseCommon = 0b01,
  RequestHeader = 0b10,
  ResponseHeader = 0b11,
  FrameTypeMask = 0b11,

  EffectiveCommon = 0b000,
  EffectiveHeader = 0b100,
  FrameEffectiveTypeMask = 0b100,

  Sentinel = 1 << 4, // internal notification, not forwarded
  Error = 1 << 5,    // ends the stream if set
};
static_assert(FrameFlags::FLAG_END_STREAM == (Error >> 5));

struct AuthState;
using AuthStateSharedPtr = std::shared_ptr<AuthState>;

class SSHRequestHeaderFrame final : public GenericProxy::RequestHeaderFrame {
public:
  SSHRequestHeaderFrame(AuthStateSharedPtr downstream_state);
  std::string_view host() const override;
  std::string_view protocol() const override { return "ssh"; }
  const AuthStateSharedPtr& authState() const;
  FrameFlags frameFlags() const override;

private:
  AuthStateSharedPtr downstream_state_;
};

class SSHResponseCommonFrame final : public GenericProxy::ResponseCommonFrame {
public:
  SSHResponseCommonFrame(wire::Message msg, FrameTags tags)
      : frame_tags_(tags),
        frame_flags_((tags & Error) >> 5),
        msg_(std::move(msg)) {}

  void setStreamId(stream_id_t stream_id) { stream_id_ = stream_id; }

  auto& message(this auto& self) { return self.msg_; }
  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::ResponseCommon | frame_tags_};
  }

private:
  FrameTags frame_tags_{0};
  uint32_t frame_flags_{0};
  stream_id_t stream_id_{0};
  wire::Message msg_;
};

class SSHResponseHeaderFrame final : public GenericProxy::ResponseHeaderFrame {
public:
  SSHResponseHeaderFrame(wire::Message msg, FrameTags tags)
      : frame_tags_(tags),
        frame_flags_((tags & Error) >> 5),
        msg_(std::move(msg)) {}

  void setStreamId(stream_id_t stream_id) { stream_id_ = stream_id; }

  StreamStatus status() const override {
    return msg_.visit(
      [](const wire::DisconnectMsg& msg) {
        return StreamStatus{static_cast<int>(*msg.reason_code), false};
      },
      [](const auto&) {
        return StreamStatus{0, true};
      });
  }
  std::string_view protocol() const override { return "ssh"; }

  auto& message(this auto& self) { return self.msg_; }
  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::ResponseHeader | frame_tags_};
  }

private:
  SSHResponseHeaderFrame() = default;
  FrameTags frame_tags_{0};
  uint32_t frame_flags_{0};
  stream_id_t stream_id_;
  wire::Message msg_;
};

class SSHRequestCommonFrame final : public GenericProxy::RequestCommonFrame {
public:
  SSHRequestCommonFrame(wire::Message msg)
      : msg_(std::move(msg)) {}

  void setStreamId(stream_id_t stream_id) { stream_id_ = stream_id; }

  auto& message(this auto& self) { return self.msg_; }
  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::RequestCommon | FrameTags::EffectiveCommon};
  }

private:
  uint32_t frame_flags_{0};
  stream_id_t stream_id_;
  wire::Message msg_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec