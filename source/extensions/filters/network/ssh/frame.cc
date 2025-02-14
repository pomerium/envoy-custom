#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SSHRequestHeaderFrame::SSHRequestHeaderFrame(AuthStateSharedPtr downstreamState)
    : downstream_state_(downstreamState) {}

std::string_view SSHRequestHeaderFrame::host() const { return downstream_state_->hostname; };

std::string_view SSHRequestHeaderFrame::protocol() const { return "ssh"; };

FrameKind SSHRequestHeaderFrame::frameKind() const { return FrameKind::RequestHeader; };

StreamStatus SSHResponseHeaderFrame::status() const { return status_; }

std::string_view SSHResponseHeaderFrame::protocol() const { return "ssh"; };

const SshMsg& SSHResponseHeaderFrame::message() const { return *msg_; }

FrameKind SSHResponseHeaderFrame::frameKind() const { return FrameKind::ResponseHeader; };

const AuthStateSharedPtr& SSHRequestHeaderFrame::authState() const { return downstream_state_; }

FrameKind SSHRequestCommonFrame::frameKind() const { return FrameKind::RequestCommon; };

const SshMsg& SSHRequestCommonFrame::message() const { return *msg_; }

FrameKind SSHResponseCommonFrame::frameKind() const { return FrameKind::ResponseCommon; };

const SshMsg& SSHResponseCommonFrame::message() const { return *msg_; }

FrameFlags SSHResponseHeaderFrame::frameFlags() const {
  if (raw_flags_.has_value()) {
    return FrameFlags(stream_id_, raw_flags_.value(), 0);
  }
  if (!status().ok()) {
    return FrameFlags(stream_id_, FrameFlags::FLAG_END_STREAM);
  }
  return FrameFlags(stream_id_, 0, 0);
}
FrameFlags SSHRequestCommonFrame::frameFlags() const { return FrameFlags(stream_id_, 0, 0); }
FrameFlags SSHResponseCommonFrame::frameFlags() const { return FrameFlags(stream_id_, 0, 0); }
FrameFlags SSHRequestHeaderFrame::frameFlags() const {
  return FrameFlags(downstream_state_->stream_id, 0, 0);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec