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

// FrameTags contains implementation-specific information about the contents of a frame.
//
// The underlying generic proxy framework has four distinct frame types, and places restrictions
// on the order in which certain frames are sent within a stream: the first frame in either
// direction must be a header frame, and all subsequent frames must be common frames.
//
// The client transport sending a response header signals to the server transport that the
// connection with the upstream client is set up, and that the downstream client has authenticated
// with the upstream. While the client transport is setting up the upstream connection, the
// downstream connection usually does not need to do anything and can just wait for the response
// header. The response header frame will contain a protocol message that signals to the downstream
// SSH client to continue. However, there are some situations where we need to send messages from
// the upstream ssh server to the downstream ssh client before the connection is fully ready, i.e.
// during authentication. One example of this is the banner message, which is forwarded directly to
// the downstream client, but does not signal any state changes, and is therefore not an "effective"
// header frame. When sending the frame containing the banner message, its actual type will be
// SSHResponseHeaderFrame (since the framework requires it) but it will have a frame tag with
// EffectiveCommon. Then, the "real" header (one of several messages, e.g. UserAuthSuccessMsg or
// ChannelOpenConfirmationMsg) would be sent as a SSHResponseCommonFrame with EffectiveHeader.
//
// See [StreamFrame::frameFlags] and [FrameFlags::frameTags] for details on how this is used.
enum FrameTags : frame_tags_type {
  ResponseCommon = 0b00, // The frame has concrete type SSHResponseCommonFrame
  RequestCommon = 0b01,  // The frame has concrete type SSHRequestCommonFrame
  ResponseHeader = 0b10, // The frame has concrete type SSHResponseHeaderFrame
  RequestHeader = 0b11,  // The frame has concrete type SSHRequestHeaderFrame
  FrameTypeMask = 0b11,

  // The frame should be treated as a common frame, regardless of its concrete type.
  EffectiveCommon = 0b000,
  // The frame should be treated as a header frame, regardless of its concrete type.
  EffectiveHeader = 0b100,
  FrameEffectiveTypeMask = 0b100,

  // The frame is an implementation-specific signal, and should be dropped by the receiving codec
  // after it is processed.
  Sentinel = 1 << 4,
  // The frame contains details about an error that has occurred. Enables the FLAG_END_STREAM and
  // FLAG_DRAIN_CLOSE frame flags if set.
  Error = 1 << 5,
};

struct AuthState;
using AuthStateSharedPtr = std::shared_ptr<AuthState>;

class SSHRequestHeaderFrame final : public GenericProxy::RequestHeaderFrame {
public:
  SSHRequestHeaderFrame(AuthStateSharedPtr auth_state);
  std::string_view host() const override;
  std::string_view protocol() const override { return "ssh"; }
  const AuthStateSharedPtr& authState() const;
  FrameFlags frameFlags() const override;

private:
  AuthStateSharedPtr auth_state_;
};

// Branchless conversion from FrameTags to matching FrameTags.
// Returns (FLAG_END_STREAM | FLAG_DRAIN_CLOSE) if tags has the Error bit set, otherwise 0.
//
// Note: this is '((tags & Error) >> 5) * 5' with the current values of Error and FrameFlags, but
// will not need to be updated if those ever change.
constexpr inline uint32_t to_frame_flags(FrameTags tags) {
  return ((tags & Error) >> std::countr_zero(std::to_underlying(Error))) *
         (FrameFlags::FLAG_END_STREAM | FrameFlags::FLAG_DRAIN_CLOSE);
}

class SSHResponseCommonFrame final : public GenericProxy::ResponseCommonFrame {
  friend wire::Message&& extractFrameMessage(const GenericProxy::StreamFrame&);

public:
  SSHResponseCommonFrame(wire::Message&& msg, FrameTags tags)
      : frame_tags_(tags),
        frame_flags_(to_frame_flags(tags)),
        msg_(std::move(msg)) {}

  void setStreamId(stream_id_t stream_id) { stream_id_ = stream_id; }

  template <typename Self>
  auto message(this Self& self) -> copy_const_t<Self, wire::Message&> {
    // return the message as const if the frame is const (as if msg_ was not mutable); instead,
    // extractFrameMessage is used in places where we need to move the contained message out of
    // a const frame.
    return self.msg_;
  }

  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::ResponseCommon | frame_tags_};
  }

private:
  FrameTags frame_tags_{};
  uint32_t frame_flags_{};
  stream_id_t stream_id_{};
  mutable wire::Message msg_;
};

class SSHResponseHeaderFrame final : public GenericProxy::ResponseHeaderFrame {
  friend wire::Message&& extractFrameMessage(const GenericProxy::StreamFrame&);

public:
  SSHResponseHeaderFrame(wire::Message&& msg, FrameTags tags)
      : frame_tags_(tags),
        frame_flags_(to_frame_flags(tags)),
        msg_(std::move(msg)) {}

  void setStreamId(stream_id_t stream_id) { stream_id_ = stream_id; }

  std::string_view protocol() const override { return "ssh"; }

  template <typename Self>
  auto message(this Self& self) -> copy_const_t<Self, wire::Message&> {
    return self.msg_;
  }

  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::ResponseHeader | frame_tags_};
  }

private:
  FrameTags frame_tags_{};
  uint32_t frame_flags_{};
  stream_id_t stream_id_{};
  mutable wire::Message msg_;
};

class SSHRequestCommonFrame final : public GenericProxy::RequestCommonFrame {
  friend wire::Message&& extractFrameMessage(const GenericProxy::StreamFrame&);

public:
  SSHRequestCommonFrame(wire::Message&& msg)
      : msg_(std::move(msg)) {}

  void setStreamId(stream_id_t stream_id) { stream_id_ = stream_id; }

  template <typename Self>
  auto message(this Self& self) -> copy_const_t<Self, wire::Message&> {
    return self.msg_;
  }

  stream_id_t streamId() const { return stream_id_; }
  FrameFlags frameFlags() const override {
    return {stream_id_, frame_flags_, FrameTags::RequestCommon | FrameTags::EffectiveCommon};
  }

private:
  uint32_t frame_flags_{};
  stream_id_t stream_id_{};
  mutable wire::Message msg_;
};

// Returns the message from a frame as an rvalue reference.
//
// Messages stored in frames are mutable, so they can be accessed as non-const even if the frame is
// const. Some callbacks originating from Envoy pass frames as const-ref, but the contents of our
// custom frame types can be safely modified since they are strictly an implementation detail.
inline wire::Message&& extractFrameMessage(const GenericProxy::StreamFrame& frame) {
  switch (frame.frameFlags().frameTags() & FrameTags::FrameTypeMask) {
  case FrameTags::ResponseCommon:
    return std::move(static_cast<const SSHResponseCommonFrame&>(frame).msg_);
  case FrameTags::RequestCommon:
    return std::move(static_cast<const SSHRequestCommonFrame&>(frame).msg_);
  case FrameTags::ResponseHeader:
    return std::move(static_cast<const SSHResponseHeaderFrame&>(frame).msg_);
  default:
    throw Envoy::EnvoyException("bug: extractFrameMessage called with RequestHeader frame");
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec