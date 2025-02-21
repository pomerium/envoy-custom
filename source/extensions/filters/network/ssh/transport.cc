#include "source/extensions/filters/network/ssh/transport.h"

#include <memory>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<size_t> TransportCallbacks::sendMessageToConnection(const wire::SshMsg& msg) {
  const auto& cs = getConnectionState();

  Envoy::Buffer::OwnedImpl dec;
  writePacket(dec, msg, cs.cipher->blockSize(MODE_WRITE), cs.cipher->aadSize(MODE_WRITE));
  Envoy::Buffer::OwnedImpl enc;
  if (auto stat = cs.cipher->encryptPacket(*cs.seq_write, enc, dec); !stat.ok()) {
    return stat;
  }
  (*cs.seq_write)++;
  if (msg.msg_type() == wire::SshMessageType::NewKeys) {
    ENVOY_LOG(debug, "resetting write seqnr");
    *cs.seq_write = 0;
  }

  size_t n = enc.length();
  writeToConnection(enc);
  return n;
}

std::unique_ptr<AuthState> AuthState::clone() {
  auto newState = std::make_unique<AuthState>();
  newState->server_version = server_version;
  newState->stream_id = stream_id;
  newState->channel_mode = channel_mode;
  newState->hijacked_stream = hijacked_stream;
  if (handoff_info.channel_info) {
    newState->handoff_info.channel_info = std::make_unique<pomerium::extensions::ssh::SSHDownstreamChannelInfo>();
    newState->handoff_info.channel_info->MergeFrom(*handoff_info.channel_info);
  }
  if (handoff_info.pty_info) {
    newState->handoff_info.pty_info = std::make_unique<pomerium::extensions::ssh::SSHDownstreamPTYInfo>();
    newState->handoff_info.pty_info->MergeFrom(*handoff_info.pty_info);
  }
  newState->username = username;
  newState->hostname = hostname;
  newState->auth_methods = auth_methods;
  newState->public_key = public_key;
  if (permissions) {
    auto newPermissions = new pomerium::extensions::ssh::Permissions;
    newPermissions->MergeFrom(*permissions);
    newState->permissions.reset(newPermissions);
  }
  return newState;
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec