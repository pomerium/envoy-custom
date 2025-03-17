#pragma once

#include "absl/status/statusor.h"
#include "envoy/config/core/v3/base.pb.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct direction_t {
  char iv_tag;
  char key_tag;
  char mac_key_tag;
};

static constexpr direction_t clientKeys{'A', 'C', 'E'};
static constexpr direction_t serverKeys{'B', 'D', 'F'};

class PacketCipher;

struct ConnectionState {
  std::unique_ptr<PacketCipher> cipher;
  std::shared_ptr<uint32_t> seq_read;
  std::shared_ptr<uint32_t> seq_write;
  direction_t direction_read;
  direction_t direction_write;
  // todo: pending key change?
};

enum class ChannelMode {
  Normal = 1,
  Hijacked = 2,
  Handoff = 3,
  Mirror = 4,
};

enum class MultiplexMode {
  None = 0,
  Source = 1,
  Mirror = 2,
};

enum class ReadWriteMode {
  ReadOnly = 0,
  ReadWrite = 1,
};

struct HandoffInfo {
  bool handoff_in_progress{false};
  std::unique_ptr<pomerium::extensions::ssh::SSHDownstreamChannelInfo> channel_info;
  std::unique_ptr<pomerium::extensions::ssh::SSHDownstreamPTYInfo> pty_info;
};

struct MultiplexingInfo {
  MultiplexMode multiplex_mode{MultiplexMode::None};
  ReadWriteMode rw_mode{ReadWriteMode::ReadOnly};
  uint64_t source_stream_id{};
  std::optional<uint64_t> downstream_channel_id;
};

struct AuthState {
  std::string server_version;
  uint64_t stream_id; // unique stream id for both connections
  ChannelMode channel_mode;
  Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>* hijacked_stream;
  HandoffInfo handoff_info;
  MultiplexingInfo multiplexing_info;

  std::unique_ptr<pomerium::extensions::ssh::AllowResponse> allow_response;

  std::unique_ptr<AuthState> clone();
};

using AuthStateSharedPtr = std::shared_ptr<AuthState>;

class TransportCallbacks : public virtual Logger::Loggable<Logger::Id::filter> {
public:
  virtual ~TransportCallbacks() = default;
  virtual absl::StatusOr<size_t> sendMessageToConnection(const wire::Message& msg);

  virtual void forward(std::unique_ptr<SSHStreamFrame> frame) PURE;
  virtual void writeToConnection(Envoy::Buffer::Instance& buf) const PURE;

  virtual const KexResult& getKexResult() const PURE;
  virtual absl::StatusOr<bytes> signWithHostKey(bytes_view in) const PURE;
  virtual const AuthState& authState() const PURE;
  virtual AuthState& authState() PURE;
  virtual const pomerium::extensions::ssh::CodecConfig& codecConfig() const PURE;

protected:
  virtual const ConnectionState& getConnectionState() const PURE;
};

class DownstreamTransportCallbacks : public virtual TransportCallbacks {
public:
  using TransportCallbacks::TransportCallbacks;
  virtual void initUpstream(AuthStateSharedPtr downstream_state) PURE;
  virtual void sendMgmtClientMessage(const ClientMessage& msg) PURE;
};

class UpstreamTransportCallbacks : public virtual TransportCallbacks {
public:
  using TransportCallbacks::TransportCallbacks;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec