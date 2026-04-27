#pragma once

#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/channel_filter_config.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SecretsProvider {
public:
  virtual ~SecretsProvider() = default;
  virtual std::vector<openssh::SSHKeySharedPtr> hostKeys() const PURE;
  virtual openssh::SSHKeySharedPtr userCaKey() const PURE;
};

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
  virtual stream_id_t streamId() const PURE;
  virtual void updatePeerExtInfo(std::optional<wire::ExtInfoMsg> msg) PURE;
  virtual Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const PURE;
  virtual void terminate(absl::Status status) PURE;
  virtual ChannelIDManager& channelIdManager() PURE;
  virtual ChannelFilterManager& channelFilterManager() PURE;
  virtual const SecretsProvider& secretsProvider() const PURE;
  virtual Stats::Scope& statsScope() const PURE;

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

DECL_BASIC_ENUM_FORMATTER(Envoy::Extensions::NetworkFilters::GenericProxy::Codec::ChannelMode);