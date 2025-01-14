#pragma once

#include "envoy/http/early_header_mutation.h"
#include "api/extensions/http/early_header_mutation/trace_context/trace_context.pb.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

class Factory : public Envoy::Http::EarlyHeaderMutationFactory {
public:
  std::string name() const override { return "envoy.http.early_header_mutation.trace_context"; }

  Envoy::Http::EarlyHeaderMutationPtr
  createExtension(const Envoy::Protobuf::Message& config,
                  Envoy::Server::Configuration::FactoryContext& context) override;

  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return Envoy::ProtobufTypes::MessagePtr{new pomerium::extensions::TraceContext};
  }
};

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation