#include "source/extensions/filters/network/ssh/config.h"

#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/client_transport.h"   // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/server_transport.h"   // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep

#pragma clang unsafe_buffer_usage begin
#include "source/common/config/utility.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

CodecFactoryPtr SshCodecFactoryConfig::createCodecFactory(
  const Protobuf::Message& config, Envoy::Server::Configuration::ServerFactoryContext& context) {
  const auto& typed_config = dynamic_cast<const pomerium::extensions::ssh::CodecConfig&>(config);
  MessageUtil::validate(typed_config, context.messageValidationVisitor());
  auto conf = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
  conf->CopyFrom(typed_config);

  auto createClient = [&context, conf]() {
    auto factory = context.clusterManager().grpcAsyncClientManager().factoryForGrpcService(
      conf->grpc_service(), context.scope(), true);
    THROW_IF_NOT_OK_REF(factory.status());
    return (*factory)->createUncachedRawAsyncClient();
  };

  return std::make_unique<SshCodecFactory>(context, conf, createClient, StreamTracker::fromContext(context));
}

REGISTER_FACTORY(SshCodecFactoryConfig, CodecFactoryConfig);

SshCodecFactory::SshCodecFactory(Envoy::Server::Configuration::ServerFactoryContext& context,
                                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                 CreateGrpcClientFunc create_grpc_client,
                                 StreamTrackerSharedPtr stream_tracker)
    : context_(context),
      config_(config),
      create_grpc_client_(create_grpc_client),
      stream_tracker_(std::move(stream_tracker)) {
  auto userCaKey = openssh::SSHKey::fromPrivateKeyDataSource(config->user_ca_key());
  if (!userCaKey.ok()) {
    throw Envoy::EnvoyException(statusToString(openssh::detail::formatDataSourceError(
      config->user_ca_key(), "ssh user ca key", userCaKey.status())));
  }
  user_ca_key_ = std::move(userCaKey).value();

  auto hostKeys = openssh::loadHostKeys(config->host_keys());
  if (!hostKeys.ok()) {
    throw Envoy::EnvoyException(statusToString(hostKeys.status()));
  }
  host_keys_ = std::move(hostKeys).value();

  // Verify that all enabled channel filters listed in the configuration exist at this time, either
  // because they are statically linked in or have been loaded from a dynamic extension (which would
  // have already happened by this point).
  if (config->enabled_channel_filter_factories_size() > 0) {
    const auto& knownFactories = Envoy::Registry::FactoryRegistry<ChannelFilterFactoryConfig>::factories();
    try {
      for (const auto& requestedFactory : config->enabled_channel_filter_factories()) {
        if (!knownFactories.contains(requestedFactory.name())) {
          throw Envoy::EnvoyException(fmt::format(
            "no registered channel filter factory found for name: '{}' "
            "(the filter may be provided by an extension which was not loaded or failed to load)",
            requestedFactory.name()));
        }
        // This should already be validated by regular proto validation
        ASSERT(requestedFactory.has_typed_config());

        // Validate the factory config here, since exceptions thrown in this context are caught
        // and handled by envoy. The ChannelFilterManager will also do this (and not discard the
        // result) later when the filter chain is created, but if an exception is thrown at that
        // time it will be fatal.

        auto emptyConfig = knownFactories.at(requestedFactory.name())->createEmptyConfigProto();
        if (auto type = TypeUtil::typeUrlToDescriptorFullName(requestedFactory.typed_config().type_url());
            type == xds::type::v3::TypedStruct::default_instance().GetTypeName()) {
          // NB: if TypedStruct is used, envoy will decode it via json round-trip and will NOT check
          // if the type_url field of the TypedStruct matches the expected type. This is probably a
          // bug. It will still cause an error if the json decode fails but the error message will
          // be very confusing. To prevent this, check the type ourselves first then use
          // translateOpaqueConfig, instead of using translateAnyToFactoryConfig.
          xds::type::v3::TypedStruct typedStruct;
          auto ok = requestedFactory.typed_config().UnpackTo(&typedStruct);
          if (!ok) {
            throw Envoy::EnvoyException("bug: malformed TypedStruct in channel filter factory config");
          }
          if (auto actualTypeName = TypeUtil::typeUrlToDescriptorFullName(typedStruct.type_url());
              actualTypeName != emptyConfig->GetTypeName()) {
            throw Envoy::EnvoyException(fmt::format(
              "type mismatch in configuration for channel filter factory '{}' (expecting {}, got {})",
              requestedFactory.name(), emptyConfig->GetTypeName(), actualTypeName));
          }
        }
        auto& visitor = context.messageValidationContext().dynamicValidationVisitor();
        THROW_IF_NOT_OK(Envoy::Config::Utility::translateOpaqueConfig(
          requestedFactory.typed_config(),
          visitor,
          *emptyConfig));
        // Validate emptyConfig the same way MessageUtil::validate does, but only using the
        // abstract message (MessageUtil::validate uses ADL to find a `Validate` function from the
        // generated code)
        if (!visitor.skipValidation()) {
          MessageUtil::checkForUnexpectedFields(*emptyConfig, visitor);
        }
        MessageUtil::validateDurationFields(*emptyConfig);
        MessageUtil::recursivePgvCheck(*emptyConfig);
      }
    } catch (const std::exception& e) {
      // TODO: fmt::formatter for std::vector<std::string_view> is currently broken in upstream
      std::vector<std::string> names;
      for (auto name : Envoy::Registry::FactoryRegistry<ChannelFilterFactoryConfig>::registeredNames(true)) {
        names.push_back(std::string(name));
      }
      ENVOY_LOG(error, "ssh filter configuration error: {}", e.what());
      ENVOY_LOG(error, "note: all known channel filter factories: {}", names);
      throw;
    }
  }
}

ServerCodecPtr SshCodecFactory::createServerCodec() const {
  return std::make_unique<SshServerTransport>(context_, config_, create_grpc_client_,
                                              stream_tracker_, *this);
}

ClientCodecPtr SshCodecFactory::createClientCodec() const {
  return std::make_unique<SshClientTransport>(context_, config_, *this);
}

ProtobufTypes::MessagePtr SshCodecFactoryConfig::createEmptyConfigProto() {
  return std::make_unique<pomerium::extensions::ssh::CodecConfig>();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec