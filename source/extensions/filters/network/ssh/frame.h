#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/extensions/filters/network/generic_proxy/interface/stream.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/common/type_traits.h"
#include <utility>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using frame_tags_type = method_info<decltype(&GenericProxy::FrameFlags::frameTags)>::return_type;

enum FrameTags : frame_tags_type {
  ResponseCommon = 0b00,
  RequestCommon = 0b01,
  ResponseHeader = 0b10,
  RequestHeader = 0b11,
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

  template <typename Self>
  auto&& message(this Self&& self) { return std::forward<Self>(self).msg_; }

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

  template <typename Self>
  auto&& message(this Self&& self) { return std::forward<Self>(self).msg_; }

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

  template <typename Self>
  auto&& message(this Self&& self) { return std::forward<Self>(self).msg_; }

  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::RequestCommon | FrameTags::EffectiveCommon};
  }

private:
  uint32_t frame_flags_{0};
  stream_id_t stream_id_;
  wire::Message msg_;
};

inline wire::Message&& extractFrameMessage(const GenericProxy::StreamFrame& frame) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
  switch (frame.frameFlags().frameTags() & FrameTags::FrameTypeMask) {
  case FrameTags::ResponseCommon:
    return std::move(const_cast<SSHResponseCommonFrame&>(static_cast<const SSHResponseCommonFrame&>(frame)))
      .message();
  case FrameTags::RequestCommon:
    return std::move(const_cast<SSHRequestCommonFrame&>(static_cast<const SSHRequestCommonFrame&>(frame)))
      .message();
  case FrameTags::ResponseHeader:
    return std::move(const_cast<SSHResponseHeaderFrame&>(static_cast<const SSHResponseHeaderFrame&>(frame)))
      .message();
  [[unlikely]]
  default:
    PANIC("bug: extractFrameMessage called with RequestHeader frame");
  }
  // NOLINTEND(cppcoreguidelines-pro-type-const-cast)
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec