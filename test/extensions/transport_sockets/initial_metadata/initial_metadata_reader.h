#pragma once

#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"
#include "test/extensions/transport_sockets/initial_metadata/initial_metadata_reader.pb.h"

namespace Envoy {
namespace test {

class InitialMetadataReader : public Network::ListenerFilter, public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  InitialMetadataReader(const pomerium::integration::initial_metadata_reader::Config& config)
      : config_(config) {}

  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override {
    callbacks_ = &cb;
    return Network::FilterStatus::StopIteration;
  }

  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override {
    if (buffer.rawSlice().len_ < maxReadBytes()) {
      return Network::FilterStatus::StopIteration;
    }

    std::string_view view(static_cast<const char*>(buffer.rawSlice().mem_), buffer.rawSlice().len_);
    if (!view.starts_with(config_.magic())) {
      if (config_.strict()) {
        ENVOY_LOG(debug, "InitialMetadataReader: rejecting request without magic header in strict mode");
        callbacks_->socket().close();
        return Network::FilterStatus::StopIteration;
      } else {
        ENVOY_LOG(debug, "InitialMetadataReader: ignoring request without magic header");
        return Network::FilterStatus::Continue;
      }
    }
    if (static_cast<size_t>(view[4]) != config_.expected_payload().size()) {
      ENVOY_LOG(error, "InitialMetadataReader: expected payload size did not match");
      callbacks_->socket().close();
      return Network::FilterStatus::StopIteration;
    }
    if (view.substr(5) != config_.expected_payload()) {
      ENVOY_LOG(error, "InitialMetadataReader: expected payload did not match");
      callbacks_->socket().close();
      return Network::FilterStatus::StopIteration;
    }
    ENVOY_LOG(debug, "InitialMetadataReader: received valid payload");
    buffer.drain(maxReadBytes());
    return Network::FilterStatus::Continue;
  }

  size_t maxReadBytes() const override {
    return 5 + config_.expected_payload().size();
  }

private:
  const pomerium::integration::initial_metadata_reader::Config config_;
  Network::ListenerFilterCallbacks* callbacks_;
};

class InitialMetadataReaderConfigFactory : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
    const Protobuf::Message& config,
    const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
    Server::Configuration::ListenerFactoryContext&) override {

    auto typedConfig = dynamic_cast<const pomerium::integration::initial_metadata_reader::Config&>(config);
    return [listener_filter_matcher, typedConfig](Network::ListenerFilterManager& filter_manager) -> void {
      filter_manager.addAcceptFilter(
        listener_filter_matcher, std::make_unique<InitialMetadataReader>(typedConfig));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<pomerium::integration::initial_metadata_reader::Config>();
  }

  std::string name() const override { return "pomerium.integration.initial_metadata_reader"; }
};

} // namespace test
} // namespace Envoy