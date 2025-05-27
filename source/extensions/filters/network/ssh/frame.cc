#include "source/extensions/filters/network/ssh/frame.h"

#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SSHRequestHeaderFrame::SSHRequestHeaderFrame(AuthStateSharedPtr auth_state)
    : auth_state_(std::move(auth_state)) {}

std::string_view SSHRequestHeaderFrame::host() const {
  RELEASE_ASSERT(auth_state_ != nullptr && auth_state_->allow_response,
                 "bug: request header frame has incomplete auth state");
  if (auth_state_->allow_response->has_upstream()) {
    return auth_state_->allow_response->upstream().hostname();
  }
  return "";
};

const AuthStateSharedPtr& SSHRequestHeaderFrame::authState() const {
  return auth_state_;
}

FrameFlags SSHRequestHeaderFrame::frameFlags() const {
  return {auth_state_->stream_id, 0, FrameTags::RequestHeader | FrameTags::EffectiveHeader};
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec