#include "source/extensions/filters/network/ssh/reverse_tunnel.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/passthrough_state.h"
#include "source/extensions/filters/network/ssh/stream_address.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/passthrough_state.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/upstream/cluster_factory_impl.h"
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.validate.h"
#include "source/extensions/io_socket/user_space/io_handle_impl.h"
#include "source/common/network/connection_impl.h"
#include "envoy/network/client_connection_factory.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "source/common/http/utility.h"
#pragma clang unsafe_buffer_usage end

using Envoy::Extensions::IoSocket::UserSpace::IoHandleFactory;

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class InternalDownstreamChannel : public Channel,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  InternalDownstreamChannel(Network::IoHandlePtr io_handle,
                            ChannelEventCallbacks& event_callbacks,
                            Envoy::Event::Dispatcher& connection_dispatcher)
      : io_handle_(std::move(io_handle)),
        connection_dispatcher_(connection_dispatcher),
        event_callbacks_(event_callbacks) {
    loadPassthroughMetadata();
  }

  absl::Status setChannelCallbacks(ChannelCallbacks& callbacks) override {
    auto stat = Channel::setChannelCallbacks(callbacks);
    ASSERT(stat.ok()); // default implementation always succeeds

    // Build and send the ChannelOpen message to the downstream.
    // Normally channels don't send their own ChannelOpen messages, but this is somewhat of a
    // special case, because the channel is owned internally.
    wire::ChannelOpenMsg open;
    open.channel_type = "forwarded-tcpip";
    open.sender_channel = callbacks_->channelId();
    open.initial_window_size = wire::ChannelWindowSize;
    open.max_packet_size = wire::ChannelMaxPacketSize;

    Buffer::OwnedImpl extra;
    auto addrData = Envoy::Http::Utility::parseAuthority(server_name_);
    wire::write_opt<wire::LengthPrefixed>(extra, std::string(addrData.host_));
    wire::write<uint32_t>(extra, 443);
    wire::write_opt<wire::LengthPrefixed>(extra, downstream_addr_->ip()->addressAsString());
    wire::write<uint32_t>(extra, downstream_addr_->ip()->port());
    open.extra = wire::flushTo<bytes>(extra);

    return callbacks.sendMessageToConnection(std::move(open));
  }

  absl::Status onChannelOpened(wire::ChannelOpenConfirmationMsg&&) override {
    connection_dispatcher_.post([this] {
      io_handle_->initializeFileEvent(
        connection_dispatcher_,
        [this](uint32_t events) {
          onFileEvent(events);
          // errors returned from this callback are fatal
          return absl::OkStatus();
        },
        ::Envoy::Event::PlatformDefaultTriggerType,
        ::Envoy::Event::FileReadyType::Read | ::Envoy::Event::FileReadyType::Closed);
    });
    if (downstream_addr_->ip()->port() == 0) {
      // channel->demoSendSocks5Connect();
    }
    pomerium::extensions::ssh::ChannelEvent ev;
    ev.set_channel_id(callbacks_->channelId());
    auto* opened = ev.mutable_internal_channel_opened();
    opened->set_channel_id(callbacks_->channelId());
    opened->set_peer_address(downstream_addr_->asStringView());

    // pomerium::extensions::ssh::StreamEvent stream_ev;
    // *stream_ev.mutable_channel_event() = ev;
    // ClientMessage msg;
    // *msg.mutable_event() = stream_ev;
    event_callbacks_.sendChannelEvent(ev);
    return absl::OkStatus();
  }

  absl::Status onChannelOpenFailed(wire::ChannelOpenFailureMsg&& msg) override {
    // this is not necessarily an error that should end the connection. we can just close the
    // io handle and send a channel event
    io_handle_->close();
    onIoHandleClosed(msg.description);
    return absl::OkStatus();
  }

  absl::Status readMessage(wire::Message&& msg) override {
    return msg.visit(
      [&](wire::ChannelDataMsg& msg) {
        Buffer::OwnedImpl buffer(msg.data->data(), msg.data->size());
        auto r = io_handle_->write(buffer);
        if (!r.ok()) {
          ENVOY_LOG(debug, "write: io error: {}", r.err_->getErrorDetails());
          return absl::OkStatus();
        }
        ENVOY_LOG(debug, "wrote {} bytes to socket", r.return_value_);
        return absl::OkStatus();
      },
      [this](wire::ChannelEOFMsg&) {
        ENVOY_LOG(debug, "got eof message");
        io_handle_->shutdown(SHUT_WR);
        return absl::OkStatus();
      },
      [this](wire::ChannelCloseMsg&) {
        ENVOY_LOG(debug, "got close message");
        if (!closed_) {
          io_handle_->close();
          onIoHandleClosed("channel closed");
        }
        return absl::OkStatus();
      },
      [&](auto& msg) {
        return absl::InternalError(fmt::format("unexpected message type: {}", msg.msg_type()));
      });
  }

private:
  void onFileEvent(uint32_t events) {
    ASSERT(connection_dispatcher_.isThreadSafe());
    if ((events & Envoy::Event::FileReadyType::Closed) != 0) {
      onIoHandleClosed("connection closed by upstream");
      return;
    }

    absl::Status status;
    if ((events & Envoy::Event::FileReadyType::Read) != 0) {
      status = readReady();
    }

    if (!status.ok()) {
      io_handle_->close();
      onIoHandleClosed(statusToString(status));
    }

    // if ((events & FileReadyType::Write) != 0) {
    //   status = writeReady();
    // }
  }

  void onIoHandleClosed(const std::string& reason) {
    ASSERT(!closed_);
    closed_ = true;

    io_handle_->resetFileEvents();
    pomerium::extensions::ssh::ChannelEvent ev;
    auto* opened = ev.mutable_internal_channel_closed();
    opened->set_channel_id(callbacks_->channelId());
    opened->set_reason(reason);
    event_callbacks_.sendChannelEvent(ev);

    wire::ChannelCloseMsg close;
    close.recipient_channel = callbacks_->channelId();
    callbacks_->sendMessageToConnection(std::move(close)).IgnoreError();

    // pomerium::extensions::ssh::StreamEvent stream_ev;
    // *stream_ev.mutable_channel_event() = ev;
    // ClientMessage msg;
    // *msg.mutable_event() = stream_ev;
    //   ASSERT(transport_dispatcher_->isThreadSafe());
    //   auto r = io_handle_->close();
    //   if (!r.ok()) {
    //     return absl::CancelledError(fmt::format("close: io error: {}", r.err_->getErrorDetails()));
    //   }
    // ENVOY_LOG(info, "socket closed", r.return_value_);
  }

  absl::Status readReady() {
    ASSERT(connection_dispatcher_.isThreadSafe());
    // Read from the transport socket and encapsulate the data into a ChannelData message, then
    // write it on the channel
    Buffer::OwnedImpl buffer;
    auto r = io_handle_->read(buffer, std::nullopt);
    if (!r.ok()) {
      return absl::CancelledError(fmt::format("read: io error: {}", r.err_->getErrorDetails()));
    }
    wire::ChannelDataMsg dataMsg;
    dataMsg.recipient_channel = callbacks_->channelId();
    dataMsg.data = wire::flushTo<bytes>(buffer);
    ENVOY_LOG(debug, "writing {} bytes to internal downstream channel {}", dataMsg.data->size(), dataMsg.recipient_channel);
    return callbacks_->sendMessageToConnection(wire::Message{std::move(dataMsg)});
  }

  void loadPassthroughMetadata() {
    auto passthroughState = Network::InternalStreamPassthroughState::fromIoHandle(*io_handle_);

    envoy::config::core::v3::Metadata passthrough_metadata;
    StreamInfo::FilterStateImpl passthrough_filter_state{StreamInfo::FilterState::LifeSpan::Connection};

    passthroughState->mergeInto(passthrough_metadata, passthrough_filter_state);

    auto* serverName = passthrough_filter_state.getDataReadOnly<RequestedServerName>(RequestedServerName::key());
    ASSERT(serverName != nullptr);
    server_name_ = serverName->value();

    auto* addr = passthrough_filter_state.getDataReadOnly<Network::AddressObject>(DownstreamSourceAddressFilterStateFactory::key());
    ASSERT(addr != nullptr);
    downstream_addr_ = addr->address();
  }

  bool closed_{false};
  Network::IoHandlePtr io_handle_;
  Envoy::Event::Dispatcher& connection_dispatcher_;

  std::string server_name_;
  Envoy::Network::Address::InstanceConstSharedPtr downstream_addr_;
  ChannelEventCallbacks& event_callbacks_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

namespace Envoy::Network {

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::InternalDownstreamChannel;

class InternalStreamSocketInterface : public Network::SocketInterface,
                                      public Logger::Loggable<Logger::Id::filter> {
public:
  explicit InternalStreamSocketInterface(std::shared_ptr<StreamTracker> stream_tracker)
      : stream_tracker_(std::move(stream_tracker)) {
    ASSERT(stream_tracker_ != nullptr);
  }

  // SocketInterface
  Network::IoHandlePtr socket(Network::Socket::Type, Network::Address::Type, Network::Address::IpVersion,
                              bool, const Network::SocketCreationOptions&) const override {
    throw Envoy::EnvoyException("not implemented");
  }
  Network::IoHandlePtr socket(Network::Socket::Type socket_type,
                              const Network::Address::InstanceConstSharedPtr addr,
                              const Network::SocketCreationOptions&) const override {
    ASSERT(socket_type == Network::Socket::Type::Stream);
    auto [local, remote] = IoHandleFactory::createIoHandlePair(std::make_unique<InternalStreamPassthroughState>());

    auto streamId = dynamic_cast<const Address::InternalStreamAddressImpl&>(*addr).streamId();
    absl::Status stat;
    auto ok = stream_tracker_->tryLock(streamId, [&](Extensions::NetworkFilters::GenericProxy::Codec::StreamContext& ctx) {
      // stat = intf.requestOpenDownstreamChannel(std::move(local));
      ENVOY_LOG(debug, "requesting new downstream channel");
      auto passthroughState = Network::InternalStreamPassthroughState::fromIoHandle(*local);
      auto start = absl::Now();
      passthroughState->notifyOnStateChange(
        Network::InternalStreamPassthroughState::Initialized,
        ctx.connection().dispatcher(),
        [&, io_handle = std::move(local)] mutable {
          auto diff = absl::Now() - start;
          ENVOY_LOG(debug, "waited {} for passthrough state initialization", absl::FormatDuration(diff));
          auto c = std::make_unique<InternalDownstreamChannel>(std::move(io_handle), ctx.eventCallbacks(), ctx.connection().dispatcher());
          auto stat = ctx.streamCallbacks().startChannel(std::move(c), std::nullopt);
          if (!stat.ok()) {
            ENVOY_LOG(error, "failed to start channel: {}", statusToString(stat.status()));
            io_handle->close();
          }
        });
      return absl::OkStatus();
    });
    if (!ok) {
      ENVOY_LOG_MISC(error, "error requesting channel: stream with ID {} not found", streamId);
      return nullptr;
    }
    if (!stat.ok()) {
      ENVOY_LOG_MISC(error, "error requesting channel: {}", statusToString(stat));
      // TODO: we can't return nullptr here, it will cause a fatal error. Instead we need to return
      // a new IoHandle and immediately close it, or something
      return nullptr;
    }
    return std::move(remote);
  }
  bool ipFamilySupported(int) override { return true; }

private:
  mutable std::shared_ptr<StreamTracker> stream_tracker_;
};

// This is only required to avoid an ASSERT in the default client connection factory which doesn't
// apply to the internal ssh tunnel connections.
class SshTunnelClientConnectionFactory : public ClientConnectionFactory,
                                         public Logger::Loggable<Logger::Id::connection> {
public:
  ~SshTunnelClientConnectionFactory() override = default;

  // Config::UntypedFactory
  std::string name() const override { return "ssh_tunnel"; }

  // Network::ClientConnectionFactory
  Network::ClientConnectionPtr createClientConnection(
    Event::Dispatcher& dispatcher, Network::Address::InstanceConstSharedPtr address,
    Network::Address::InstanceConstSharedPtr source_address,
    Network::TransportSocketPtr&& transport_socket,
    const Network::ConnectionSocket::OptionsSharedPtr& options,
    const Network::TransportSocketOptionsConstSharedPtr& transport_options) override {
    ENVOY_LOG(info, "SshTunnelClientConnectionFactory::createClientConnection");
    return std::make_unique<ClientConnectionImpl>(
      dispatcher, address, source_address, std::move(transport_socket), options, transport_options);
  }
};
REGISTER_FACTORY(SshTunnelClientConnectionFactory, ClientConnectionFactory);

} // namespace Envoy::Network

namespace Envoy::Upstream {

struct CreateClusterInfoParams {
  Server::Configuration::ServerFactoryContext& server_context_;
  const envoy::config::cluster::v3::Cluster& cluster_;
  const std::optional<const envoy::config::core::v3::BindConfig>& bind_config_;
  Stats::Scope& scope_;
  const bool added_via_api_;
};

ClusterInfoConstSharedPtr createClusterInfo(CreateClusterInfoParams params) {
  Envoy::Stats::ScopeSharedPtr scope =
    params.scope_.createScope(fmt::format("cluster.{}.", params.cluster_.name()));

  Envoy::Server::Configuration::TransportSocketFactoryContextImpl factory_context(
    params.server_context_, *scope, params.server_context_.messageValidationVisitor());

  // TODO(JimmyCYJ): Support SDS for HDS cluster.
  Network::UpstreamTransportSocketFactoryPtr socket_factory = THROW_OR_RETURN_VALUE(
    Upstream::createTransportSocketFactory(params.cluster_, factory_context),
    Network::UpstreamTransportSocketFactoryPtr);
  auto socket_matcher = THROW_OR_RETURN_VALUE(
    TransportSocketMatcherImpl::create(params.cluster_.transport_socket_matches(),
                                       factory_context, socket_factory, *scope),
    std::unique_ptr<TransportSocketMatcherImpl>);

  return THROW_OR_RETURN_VALUE(
    ClusterInfoImpl::create(params.server_context_.initManager(), params.server_context_,
                            params.cluster_, params.bind_config_,
                            params.server_context_.runtime(), std::move(socket_matcher),
                            std::move(scope), params.added_via_api_, factory_context),
    std::unique_ptr<ClusterInfoImpl>);
}

class InternalStreamHost : public HostImpl {
public:
  static absl::StatusOr<HostSharedPtr>
  create(stream_id_t id,
         const envoy::config::cluster::v3::Cluster& cluster,
         Server::Configuration::ServerFactoryContext& server_context,
         std::shared_ptr<Network::SocketInterface> socket_interface) {
    absl::Status creation_status = absl::OkStatus();
    auto ret = absl::WrapUnique(new InternalStreamHost(creation_status, id, cluster, server_context, socket_interface));
    RETURN_IF_NOT_OK(creation_status);
    return ret;
  }

  stream_id_t streamId() const { return id_; }

protected:
  InternalStreamHost(absl::Status& creation_status,
                     stream_id_t stream_id,
                     const envoy::config::cluster::v3::Cluster& cluster,
                     Server::Configuration::ServerFactoryContext& server_context,
                     std::shared_ptr<Network::SocketInterface> socket_interface)
      : HostImpl(creation_status,
                 createClusterInfo({
                   .server_context_ = server_context,
                   .cluster_ = cluster,
                   .bind_config_ = server_context.clusterManager().bindConfig(),
                   .scope_ = server_context.scope(),
                   .added_via_api_ = true,
                 }),
                 fmt::format("ssh:{}", stream_id),
                 std::make_shared<Network::Address::InternalStreamAddressImpl>(stream_id, socket_interface), nullptr, nullptr, 1,
                 envoy::config::core::v3::Locality().default_instance(),
                 envoy::config::endpoint::v3::Endpoint::HealthCheckConfig().default_instance(),
                 0, envoy::config::core::v3::HEALTHY, server_context.timeSource()),
        id_(stream_id) {}

  stream_id_t id_;
};

absl::StatusOr<std::unique_ptr<SshReverseTunnelCluster>>
SshReverseTunnelCluster::create(const envoy::config::cluster::v3::Cluster& cluster,
                                const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                                ClusterFactoryContext& cluster_context) {
  absl::Status creation_status = absl::OkStatus();
  auto ret = absl::WrapUnique(new SshReverseTunnelCluster(cluster, proto_config, cluster_context, creation_status));
  RETURN_IF_NOT_OK(creation_status);
  return ret;
}

SshReverseTunnelCluster::SshReverseTunnelCluster(const envoy::config::cluster::v3::Cluster& cluster,
                                                 const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                                                 ClusterFactoryContext& cluster_context,
                                                 absl::Status& creation_status)
    : ClusterImplBase(cluster, cluster_context, creation_status),
      Envoy::Config::SubscriptionBase<envoy::config::endpoint::v3::ClusterLoadAssignment>(
        cluster_context.messageValidationVisitor(), "cluster_name"),
      cluster_(cluster),
      server_context_(cluster_context.serverFactoryContext()),
      config_(proto_config),
      stream_tracker_(StreamTracker::fromContext(cluster_context.serverFactoryContext())),
      socket_interface_(std::make_shared<Network::InternalStreamSocketInterface>(stream_tracker_)),
      dispatcher_(cluster_context.serverFactoryContext().mainThreadDispatcher()) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  RETURN_ONLY_IF_NOT_OK_REF(creation_status);

  auto stat =
    cluster_context
      .clusterManager()
      .subscriptionFactory()
      .subscriptionFromConfigSource(
        proto_config.eds_config(),
        "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
        info_->statsScope(), *this, resource_decoder_, {});
  SET_AND_RETURN_IF_NOT_OK(stat.status(), creation_status);
  eds_subscription_ = std::move(stat).value();
}

void SshReverseTunnelCluster::startPreInit() {
  ENVOY_LOG(info, "starting EDS subscription (cluster={})", cluster_.name());
  eds_subscription_->start({info_->name()});
}

absl::Status SshReverseTunnelCluster::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                                                     const std::string&) {
  if (resources.empty()) {
    ENVOY_LOG(info, "Missing ClusterLoadAssignment for {} in onConfigUpdate()", edsServiceName());
    info_->configUpdateStats().update_empty_.inc();
    return absl::OkStatus();
  }
  if (resources.size() != 1) {
    return absl::InvalidArgumentError(
      fmt::format("Unexpected EDS resource length: {}", resources.size()));
  }
  ENVOY_LOG(info, "received EDS update for cluster {}", edsServiceName());
  const auto& cluster_load_assignment =
    dynamic_cast<const endpointv3::ClusterLoadAssignment&>(resources[0].get().resource());
  if (cluster_load_assignment.cluster_name() != edsServiceName()) {
    return absl::InvalidArgumentError(fmt::format("Unexpected EDS cluster (expecting {}): {}",
                                                  edsServiceName(),
                                                  cluster_load_assignment.cluster_name()));
  }

  // TODO: handle endpoint_stale_after

  return update(cluster_load_assignment);
}
absl::Status SshReverseTunnelCluster::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                                                     const Protobuf::RepeatedPtrField<std::string>&,
                                                     const std::string&) {
  return onConfigUpdate(added_resources, "");
}
void SshReverseTunnelCluster::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason reason, const EnvoyException*) {
  switch (reason) {
  case Config::ConfigUpdateFailureReason::ConnectionFailure:
    ENVOY_LOG(error, "onConfigUpdateFailed for cluster {}: connection failure ", edsServiceName());
    break;
  case Config::ConfigUpdateFailureReason::FetchTimedout:
    ENVOY_LOG(error, "onConfigUpdateFailed for cluster {}: fetch timeout", edsServiceName());
    break;
  case Config::ConfigUpdateFailureReason::UpdateRejected:
    ENVOY_LOG(error, "onConfigUpdateFailed for cluster {}: update rejected", edsServiceName());
    break;
  }
  // TODO: handle this
  // update({}).IgnoreError();
}
absl::StatusOr<HostSharedPtr> SshReverseTunnelCluster::newHostForStreamId(stream_id_t id) {
  return InternalStreamHost::create(id, cluster_, server_context_, socket_interface_);
}
absl::Status SshReverseTunnelCluster::update(const envoy::config::endpoint::v3::ClusterLoadAssignment& cluster_load_assignment) {
  // only using one priority here (0)
  constexpr uint32_t priority = 0;
  const auto& hostSet = priority_set_.getOrCreateHostSet(priority).hosts();

  const auto& hostMap = priority_set_.crossPriorityHostMap();
  std::unordered_set<std::string> updatedEndpoints{};
  for (const auto& locality_lb_endpoint : cluster_load_assignment.endpoints()) {
    for (const auto& lb_endpoint : locality_lb_endpoint.lb_endpoints()) {
      updatedEndpoints.insert(lb_endpoint.endpoint_name());
    }
  }

  HostVector hostsToAdd;
  HostVector hostsToRemove;
  for (const auto& [key, value] : *hostMap) {
    if (!updatedEndpoints.contains(key)) {
      hostsToRemove.push_back(value);
    }
  }
  for (const auto& endpointName : updatedEndpoints) {
    auto endpointNameView = std::string_view(endpointName);
    if (!hostMap->contains(endpointNameView)) {
      constexpr auto prefix = "ssh:"sv;
      if (!endpointNameView.starts_with(prefix)) {
        return absl::InternalError("invalid lb endpoint name '{}' (expecting format 'ssh:<id>')");
      }
      endpointNameView.remove_prefix(prefix.size());
      stream_id_t streamId{};
      if (!absl::SimpleAtoi(endpointNameView, &streamId)) {
        return absl::InternalError("bug: invalid lb endpoint name (expecting stream ID)");
      }

      auto newHost = newHostForStreamId(streamId);
      if (!newHost.ok()) {
        return statusf("failed to create host for stream ID: {}", newHost.status());
      }
      hostsToAdd.push_back(std::move(newHost).value());
    }
  }

  HostVectorSharedPtr filteredHostSetCopy(new HostVector());
  // copy all the existing hosts, except those that have been removed
  std::copy_if(hostSet.begin(), hostSet.end(), std::back_inserter(*filteredHostSetCopy),
               [&](const HostSharedPtr& host) {
                 return !std::ranges::contains(hostsToRemove, host);
               });
  // copy all the new hosts
  std::copy(hostsToAdd.begin(), hostsToAdd.end(), std::back_inserter(*filteredHostSetCopy));

  ENVOY_LOG(info, "updating endpoints for cluster {}: {} added, {} removed, {} total", edsServiceName(),
            hostsToAdd.size(), hostsToRemove.size(), filteredHostSetCopy->size());
  priority_set_.updateHosts(priority,
                            HostSetImpl::partitionHosts(filteredHostSetCopy, HostsPerLocalityImpl::empty()), {},
                            std::move(hostsToAdd),
                            std::move(hostsToRemove),
                            server_context_.api().randomGenerator().random(),
                            std::nullopt, std::nullopt);

  onPreInitComplete(); // the first valid update will complete cluster initialization
  return absl::OkStatus();
}

SshReverseTunnelClusterFactory::SshReverseTunnelClusterFactory()
    : ConfigurableClusterFactoryBase("envoy.clusters.ssh_reverse_tunnel") {}

absl::StatusOr<std::pair<Upstream::ClusterImplBaseSharedPtr, Upstream::ThreadAwareLoadBalancerPtr>>
SshReverseTunnelClusterFactory::createClusterWithConfig(const envoy::config::cluster::v3::Cluster& cluster,
                                                        const pomerium::extensions::ssh::ReverseTunnelCluster& proto_config,
                                                        Upstream::ClusterFactoryContext& context) {
  auto c = SshReverseTunnelCluster::create(cluster, proto_config, context);
  if (!c.ok()) {
    return c.status();
  }
  return {{std::move(c).value(), nullptr}};
}

REGISTER_FACTORY(SshReverseTunnelClusterFactory, ClusterFactory);

} // namespace Envoy::Upstream