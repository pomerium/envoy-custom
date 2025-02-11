#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::StatusOr<size_t> TransportCallbacks::sendMessageToConnection(const SshMsg& msg) {
  const auto& cs = getConnectionState();

  Envoy::Buffer::OwnedImpl dec;
  writePacket(dec, msg, cs.cipher->blockSize(MODE_WRITE), cs.cipher->aadSize(MODE_WRITE));
  Envoy::Buffer::OwnedImpl enc;
  if (auto stat = cs.cipher->encryptPacket(*cs.seq_write, enc, dec); !stat.ok()) {
    return stat;
  }
  (*cs.seq_write)++;
  if (msg.msg_type() == SshMessageType::NewKeys) {
    ENVOY_LOG(debug, "resetting write seqnr");
    *cs.seq_write = 0;
  }

  size_t n = enc.length();
  writeToConnection(enc);
  return n;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec