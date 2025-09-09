#pragma once

#include "source/common/id_alloc.h"
#include "source/extensions/filters/network/ssh/id_manager.h"
#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr DirectionTags clientKeys{'A', 'C', 'E'};
static constexpr DirectionTags serverKeys{'B', 'D', 'F'};

enum class ChannelMode {
  // Normal mode: the channel is being proxied directly to the upstream.
  Normal = 1,

  // Hijacked mode: only the server codec is active, and the upstream side of the channel is being
  // redirected to Pomerium.
  Hijacked = 2,

  // Handoff mode: the channel was previously in Hijacked mode, but Pomerium has handed off the
  // upstream side of the channel to the real upstream server. This is a permanent state, and
  // signals some extra logic such as performing channel ID translation.
  Handoff = 3,

  // Mirror mode: no upstream; contents are duplicated from a different channel to mirror its state.
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
  bool handoff_in_progress{};
  std::unique_ptr<pomerium::extensions::ssh::SSHDownstreamChannelInfo> channel_info;
  std::unique_ptr<pomerium::extensions::ssh::SSHDownstreamPTYInfo> pty_info;
};

struct MultiplexingInfo {
  MultiplexMode multiplex_mode{MultiplexMode::None};
  ReadWriteMode rw_mode{ReadWriteMode::ReadOnly};
  stream_id_t source_stream_id{};
  std::optional<uint32_t> downstream_channel_id;
};

struct AuthInfo : public StreamInfo::FilterState::Object {
  std::string server_version;
  stream_id_t stream_id{}; // unique stream id for both connections
  ChannelMode channel_mode{};
  HandoffInfo handoff_info;
  MultiplexingInfo multiplexing_info;
  std::optional<wire::ExtInfoMsg> downstream_ext_info;
  std::optional<wire::ExtInfoMsg> upstream_ext_info;
  std::unique_ptr<pomerium::extensions::ssh::AllowResponse> allow_response;
};

using AuthInfoSharedPtr = std::shared_ptr<AuthInfo>;

class TransportCallbacks {
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
  virtual AuthInfo& authInfo() PURE;
  virtual const pomerium::extensions::ssh::CodecConfig& codecConfig() const PURE;
  virtual stream_id_t streamId() const PURE;
  virtual void updatePeerExtInfo(std::optional<wire::ExtInfoMsg> msg) PURE;
  virtual Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const PURE;
  virtual void terminate(absl::Status status) PURE;
  virtual ChannelIDManager& channelIdManager() PURE;

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
  virtual void initUpstream(AuthInfoSharedPtr auth_info) PURE;
  virtual void onServiceAuthenticated(const std::string& service_name) PURE;
  virtual void sendMgmtClientMessage(const ClientMessage& msg) PURE;
};

class UpstreamTransportCallbacks : public virtual TransportCallbacks {};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
