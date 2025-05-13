#pragma once

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr DirectionTags clientKeys{'A', 'C', 'E'};
static constexpr DirectionTags serverKeys{'B', 'D', 'F'};

class PacketCipher;

struct CipherState {
  bool pending_key_exchange{};
  std::unique_ptr<PacketCipher> cipher;
  uint32_t seq_read{};
  uint32_t seq_write{};
  uint64_t read_bytes_remaining{};
  uint64_t write_bytes_remaining{};
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
  stream_id_t source_stream_id{};
  std::optional<uint32_t> downstream_channel_id;
};

struct AuthState {
  std::string server_version;
  stream_id_t stream_id; // unique stream id for both connections
  ChannelMode channel_mode;
  std::weak_ptr<Grpc::AsyncStream<pomerium::extensions::ssh::ChannelMessage>> hijacked_stream;
  HandoffInfo handoff_info;
  MultiplexingInfo multiplexing_info;
  std::optional<wire::ExtInfoMsg> downstream_ext_info;
  std::optional<wire::ExtInfoMsg> upstream_ext_info;

  std::unique_ptr<pomerium::extensions::ssh::AllowResponse> allow_response;

  std::unique_ptr<AuthState> clone();
};

using AuthStateSharedPtr = std::shared_ptr<AuthState>;

class TransportCallbacks : public virtual Logger::Loggable<Logger::Id::filter> {
  friend class Kex;              // uses reset{Read|Write}SequenceNumber and sendMessageDirect
  friend class VersionExchanger; // uses writeToConnection

public:
  virtual ~TransportCallbacks() = default;
  virtual absl::StatusOr<size_t> sendMessageToConnection(wire::Message&& msg) PURE;

  virtual void forward(wire::Message&& msg, FrameTags tags = EffectiveCommon) PURE;
  virtual void forwardHeader(wire::Message&& msg, FrameTags tags = {}) {
    forward(std::move(msg), FrameTags{tags | EffectiveHeader});
  };

  virtual const bytes& sessionId() const PURE;
  virtual absl::StatusOr<bytes> signWithHostKey(bytes_view in) const PURE;
  virtual const AuthState& authState() const PURE;
  virtual AuthState& authState() PURE;
  virtual const pomerium::extensions::ssh::CodecConfig& codecConfig() const PURE;
  virtual stream_id_t streamId() const PURE;
  virtual void updatePeerExtInfo(std::optional<wire::ExtInfoMsg> msg) PURE;

  // This function is called at each opportunity to send ext info (once for clients, twice for
  // servers). Iff a value is returned, it will be sent to the peer.
  virtual std::optional<wire::ExtInfoMsg> outgoingExtInfo() PURE;

  // Returns a copy of the latest peer extension info, if any.
  virtual std::optional<wire::ExtInfoMsg> peerExtInfo() const PURE;

protected:
  virtual void writeToConnection(Envoy::Buffer::Instance& buf) const PURE;
  virtual absl::StatusOr<size_t> sendMessageDirect(wire::Message&& msg) PURE;
  virtual uint64_t resetReadSequenceNumber() PURE;
  virtual uint64_t resetWriteSequenceNumber() PURE;
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