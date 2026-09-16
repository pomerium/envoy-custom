#include "source/extensions/transport_sockets/initial_metadata/filter_state_objects.h"
#include "envoy/registry/registry.h"

namespace Envoy::Extensions::TransportSockets {

InitialMetadataPayload::InitialMetadataPayload(std::string_view payload)
    : payload_(payload) {}

const std::string& InitialMetadataPayload::payload() const {
  return payload_;
}

const std::string& InitialMetadataPayload::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "pomerium.initial_metadata_payload");
}

std::string InitialMetadataPayloadFilterStateFactory::name() const {
  return key();
}

const std::string& InitialMetadataPayloadFilterStateFactory::key() {
  return InitialMetadataPayload::key();
}

std::unique_ptr<StreamInfo::FilterState::Object>
InitialMetadataPayloadFilterStateFactory::createFromBytes(std::string_view data) const {
  return std::make_unique<InitialMetadataPayload>(data);
}

REGISTER_FACTORY(InitialMetadataPayloadFilterStateFactory, StreamInfo::FilterState::ObjectFactory);

} // namespace Envoy::Extensions::TransportSockets