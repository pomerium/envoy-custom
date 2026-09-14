#pragma once

#include "envoy/stream_info/filter_state.h"

namespace Envoy::Extensions::TransportSockets {

class InitialMetadataPayload : public StreamInfo::FilterState::Object {
public:
  InitialMetadataPayload(std::string_view payload);
  const std::string& payload() const;
  static const std::string& key();

private:
  const std::string payload_;
};

class InitialMetadataPayloadFilterStateFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override;
  static const std::string& key();
  std::unique_ptr<StreamInfo::FilterState::Object> createFromBytes(std::string_view data) const override;
};
} // namespace Envoy::Extensions::TransportSockets