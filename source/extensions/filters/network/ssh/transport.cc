#include "source/extensions/filters/network/ssh/transport.h"

#include <memory>

#include "api/extensions/filters/network/ssh/ssh.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

std::unique_ptr<AuthState> AuthState::clone() {
  auto newState = std::make_unique<AuthState>();
  newState->server_version = server_version;
  newState->stream_id = stream_id;
  newState->channel_mode = channel_mode;
  newState->hijacked_stream = hijacked_stream;
  if (handoff_info.channel_info) {
    newState->handoff_info.channel_info = std::make_unique<pomerium::extensions::ssh::SSHDownstreamChannelInfo>();
    newState->handoff_info.channel_info->CopyFrom(*handoff_info.channel_info);
  }
  if (handoff_info.pty_info) {
    newState->handoff_info.pty_info = std::make_unique<pomerium::extensions::ssh::SSHDownstreamPTYInfo>();
    newState->handoff_info.pty_info->CopyFrom(*handoff_info.pty_info);
  }
  if (allow_response) {
    newState->allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
    newState->allow_response->CopyFrom(*allow_response);
  }
  return newState;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec