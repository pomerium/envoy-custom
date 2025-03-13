#include "source/extensions/filters/network/ssh/frame.h"

#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SSHRequestHeaderFrame::SSHRequestHeaderFrame(AuthStateSharedPtr downstream_state)
    : downstream_state_(downstream_state) {}

std::string_view SSHRequestHeaderFrame::host() const {
  if (downstream_state_->allow_response->has_upstream()) {
    return downstream_state_->allow_response->upstream().hostname();
  }
  return "";
};

std::string_view SSHRequestHeaderFrame::protocol() const {
  return "ssh";
};

FrameKind SSHRequestHeaderFrame::frameKind() const {
  return FrameKind::RequestHeader;
};

StreamStatus SSHResponseHeaderFrame::status() const {
  return status_;
}

std::string_view SSHResponseHeaderFrame::protocol() const {
  return "ssh";
};

wire::Message& SSHResponseHeaderFrame::message() const {
  return *msg_;
}

FrameKind SSHResponseHeaderFrame::frameKind() const {
  return FrameKind::ResponseHeader;
};

const AuthStateSharedPtr& SSHRequestHeaderFrame::authState() const {
  return downstream_state_;
}

FrameKind SSHRequestCommonFrame::frameKind() const {
  return FrameKind::RequestCommon;
};

wire::Message& SSHRequestCommonFrame::message() const {
  return *msg_;
}

FrameKind SSHResponseCommonFrame::frameKind() const {
  return FrameKind::ResponseCommon;
};

wire::Message& SSHResponseCommonFrame::message() const {
  return *msg_;
}

FrameFlags SSHResponseHeaderFrame::frameFlags() const {
  if (raw_flags_.has_value()) {
    return {stream_id_, raw_flags_.value(), 0};
  }
  if (!status().ok()) {
    return {stream_id_, FrameFlags::FLAG_END_STREAM};
  }
  return {stream_id_, 0, 0};
}

FrameFlags SSHRequestCommonFrame::frameFlags() const {
  return {stream_id_, 0, 0};
}

FrameFlags SSHResponseCommonFrame::frameFlags() const {
  return {stream_id_, 0, 0};
}

FrameFlags SSHRequestHeaderFrame::frameFlags() const {
  return {downstream_state_->stream_id, 0, 0};
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec