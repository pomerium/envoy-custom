#include "source/extensions/filters/network/ssh/frame.h"

#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SSHRequestHeaderFrame::SSHRequestHeaderFrame(AuthStateSharedPtr downstream_state)
    : downstream_state_(std::move(downstream_state)) {}

std::string_view SSHRequestHeaderFrame::host() const {
  if (downstream_state_->allow_response->has_upstream()) {
    return downstream_state_->allow_response->upstream().hostname();
  }
  return "";
};

const AuthStateSharedPtr& SSHRequestHeaderFrame::authState() const {
  return downstream_state_;
}

FrameFlags SSHRequestHeaderFrame::frameFlags() const {
  return {downstream_state_->stream_id, 0, FrameTags::RequestHeader | FrameTags::EffectiveHeader};
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec