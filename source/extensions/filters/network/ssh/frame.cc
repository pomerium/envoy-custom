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

const AuthStateSharedPtr& SSHRequestHeaderFrame::authState() const {
  return downstream_state_;
}

FrameFlags SSHRequestHeaderFrame::frameFlags() const {
  return {downstream_state_->stream_id, 0, 0};
}

SSHResponseHeaderFrame::SSHResponseHeaderFrame(stream_id_t stream_id)
    : status_(0, true),
      stream_id_(stream_id),
      raw_flags_(0),
      is_sentinel_(true) {}

StreamStatus SSHResponseHeaderFrame::status() const {
  return status_;
}

std::string_view SSHResponseHeaderFrame::protocol() const {
  return "ssh";
};

FrameFlags SSHResponseHeaderFrame::frameFlags() const {
  if (raw_flags_.has_value()) {
    return {stream_id_, raw_flags_.value(), 0};
  }
  if (!status().ok()) {
    return {stream_id_, FrameFlags::FLAG_END_STREAM};
  }
  return {stream_id_, 0, 0};
}

FrameKind SSHResponseHeaderFrame::frameKind() const {
  return FrameKind::ResponseHeader;
};

stream_id_t SSHResponseHeaderFrame::streamId() const {
  return stream_id_;
}

void SSHResponseHeaderFrame::setRawFlags(uint32_t raw_flags) {
  raw_flags_ = raw_flags;
}

void SSHResponseHeaderFrame::setStatus(StreamStatus status) {
  status_ = status;
};

bool SSHResponseHeaderFrame::isSentinel() const {
  return is_sentinel_;
}

FrameKind SSHRequestCommonFrame::frameKind() const {
  return FrameKind::RequestCommon;
};

FrameKind SSHResponseCommonFrame::frameKind() const {
  return FrameKind::ResponseCommon;
};

FrameFlags SSHRequestCommonFrame::frameFlags() const {
  if (raw_flags_.has_value()) {
    return {stream_id_, raw_flags_.value(), 0};
  }
  return {stream_id_, 0, 0};
}

stream_id_t SSHRequestCommonFrame::streamId() const {
  return stream_id_;
}

FrameFlags SSHResponseCommonFrame::frameFlags() const {
  if (raw_flags_.has_value()) {
    return {stream_id_, raw_flags_.value(), 0};
  }
  return {stream_id_, 0, 0};
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec