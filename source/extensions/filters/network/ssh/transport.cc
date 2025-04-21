#include "source/extensions/filters/network/ssh/transport.h"

#include <memory>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<size_t> TransportCallbacks::sendMessageToConnection(const wire::Message& msg) {
  const auto& cs = getConnectionState();

  Envoy::Buffer::OwnedImpl dec;
  auto stat = wire::encodePacket(dec, msg, cs.cipher->blockSize(ModeWrite), cs.cipher->aadSize(ModeWrite));
  if (!stat.ok()) {
    return statusf("error encoding packet: {}", stat.status());
  }
  Envoy::Buffer::OwnedImpl enc;
  if (auto stat = cs.cipher->encryptPacket(*cs.seq_write, enc, dec); !stat.ok()) {
    return statusf("error encrypting packet: {}", stat);
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