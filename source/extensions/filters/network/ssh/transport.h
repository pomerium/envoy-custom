#pragma once

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/ssh/util.h"
#include "absl/status/statusor.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class PacketCipher;
struct SshMsg;

struct direction_t {
  bytearray iv_tag;
  bytearray key_tag;
  bytearray mac_key_tag;
};

static const direction_t clientKeys{{'A'}, {'C'}, {'E'}};
static const direction_t serverKeys{{'B'}, {'D'}, {'F'}};

struct connection_state_t {
  std::unique_ptr<PacketCipher> cipher;
  std::shared_ptr<uint32_t> seq_read;
  std::shared_ptr<uint32_t> seq_write;
  direction_t direction_read;
  direction_t direction_write;
  // todo: pending key change?
};

class TransportCallbacks {
public:
  virtual ~TransportCallbacks() = default;
  absl::StatusOr<size_t> sendMessageToConnection(const SshMsg& msg);

  virtual void initUpstream(std::string_view username, std::string_view hostname) PURE;
  virtual void writeToConnection(Envoy::Buffer::Instance& buf) const PURE;

protected:
  virtual const connection_state_t& getConnectionState() const PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec