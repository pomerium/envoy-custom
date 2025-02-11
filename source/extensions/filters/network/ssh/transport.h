#pragma once

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "absl/status/statusor.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class PacketCipher;
struct SshMsg;
struct kex_result_t;

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

struct PubKeyUserAuthRequestMsg;

struct downstream_state_t {
  std::string server_version;
  uint64_t stream_id; // unique stream id for both connections

  std::string username;
  std::string hostname;
  std::unique_ptr<PubKeyUserAuthRequestMsg> pubkey;
};

class TransportCallbacks : public virtual Logger::Loggable<Logger::Id::filter> {
public:
  virtual ~TransportCallbacks() = default;
  absl::StatusOr<size_t> sendMessageToConnection(const SshMsg& msg);

  virtual void initUpstream(std::shared_ptr<downstream_state_t> downstreamState) PURE;
  virtual void forward(std::unique_ptr<SSHStreamFrame> frame) PURE;
  virtual void writeToConnection(Envoy::Buffer::Instance& buf) const PURE;

  virtual const kex_result_t& getKexResult() const PURE;
  virtual absl::StatusOr<bytearray> signWithHostKey(Envoy::Buffer::Instance& in) const PURE;
  virtual const downstream_state_t& getDownstreamState() const PURE;

protected:
  virtual const connection_state_t& getConnectionState() const PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec