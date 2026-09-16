#include "source/extensions/transport_sockets/common/passthrough.h"
#include "api/extensions/transport_sockets/initial_metadata/initial_metadata.pb.h"
#include "api/extensions/transport_sockets/initial_metadata/initial_metadata.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"
#include "source/common/config/utility.h"
#include "source/extensions/transport_sockets/initial_metadata/filter_state_objects.h"

namespace Envoy::Extensions::TransportSockets {

using InitialMetadataConfig = pomerium::extensions::transport_sockets::initial_metadata::Config;

class InitialMetadataTransportSocket : public PassthroughSocket,
                                       public Logger::Loggable<Logger::Id::filter> {
public:
  InitialMetadataTransportSocket(const InitialMetadataConfig& config, Network::TransportSocketPtr&& inner_socket)
      : PassthroughSocket(std::move(inner_socket)),
        config_(config) {}

  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override {
    callbacks_ = &callbacks;
    PassthroughSocket::setTransportSocketCallbacks(callbacks);
  }

  void onConnected() override {
    sendInitialMetadata();
    PassthroughSocket::onConnected();
  }

private:
  void sendInitialMetadata() {
    const auto* payloadObject =
      callbacks_->connection()
        .streamInfo()
        .filterState()
        ->getDataReadOnly<InitialMetadataPayload>(InitialMetadataPayload::key());
    std::string_view payload{};
    if (payloadObject != nullptr) {
      ENVOY_LOG(trace, "initial_metadata: payload filter state object found");
      payload = payloadObject->payload();
    } else if (config_.has_default_payload()) {
      ENVOY_LOG(trace, "initial_metadata: payload filter state object not found, using configured default");
      payload = config_.default_payload().value();
    } else {
      ENVOY_LOG(trace, "initial_metadata: payload filter state object not found and no default configured, nothing to do");
      return;
    }

    if (payload.size() > 255) {
      ENVOY_LOG(error, "initial_metadata: payload size {} is greater than the max allowed size ({}), not sending",
                payload.size(), 255);
      return;
    }

    Buffer::OwnedImpl buf;
    buf.add(config_.magic());
    buf.writeByte(static_cast<uint8_t>(payload.size()));
    buf.add(payload);
    ENVOY_LOG(debug, "initial_metadata: writing {} bytes to socket", buf.length());
    callbacks_->ioHandle().write(buf);
  }

  const InitialMetadataConfig config_;
  Network::TransportSocketCallbacks* callbacks_{};
};

class InitialMetadataSocketFactory : public PassthroughFactory {
public:
  InitialMetadataSocketFactory(const InitialMetadataConfig& config,
                               Network::UpstreamTransportSocketFactoryPtr&& inner_socket_factory)
      : PassthroughFactory(std::move(inner_socket_factory)),
        config_(config) {
  }

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        Upstream::HostDescriptionConstSharedPtr host) const override {
    return std::make_unique<InitialMetadataTransportSocket>(
      config_,
      transport_socket_factory_->createTransportSocket(std::move(options), std::move(host)));
  }

private:
  const InitialMetadataConfig config_;
};

class InitialMetadataSocketConfigFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "pomerium.transport_sockets.initial_metadata"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<InitialMetadataConfig>();
  }
  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr> createTransportSocketFactory(
    const Protobuf::Message& config,
    Server::Configuration::TransportSocketFactoryContext& context) override {
    const auto& typedConfig = MessageUtil::downcastAndValidate<const InitialMetadataConfig&>(
      config, context.messageValidationVisitor());

    auto& innerConfigFactory = Envoy::Config::Utility::getAndCheckFactory<
      Server::Configuration::UpstreamTransportSocketConfigFactory>(typedConfig.transport_socket());

    auto innerConfigFactoryConfig = Config::Utility::translateToFactoryConfig(
      typedConfig.transport_socket(), context.messageValidationVisitor(), innerConfigFactory);

    auto innerSocketFactory =
      innerConfigFactory.createTransportSocketFactory(*innerConfigFactoryConfig, context);
    RETURN_IF_NOT_OK_REF(innerSocketFactory.status());

    return std::make_unique<InitialMetadataSocketFactory>(
      typedConfig, std::move(innerSocketFactory).value());
  }
};

REGISTER_FACTORY(InitialMetadataSocketConfigFactory,
                 Envoy::Server::Configuration::UpstreamTransportSocketConfigFactory);
} // namespace Envoy::Extensions::TransportSockets
