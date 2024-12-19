#include "source/extensions/http/early_header_mutation/trace_context/config.h"
#include "source/extensions/http/early_header_mutation/trace_context/trace_context.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

Envoy::Http::EarlyHeaderMutationPtr
Factory::createExtension(const Envoy::Protobuf::Message&,
                         Envoy::Server::Configuration::FactoryContext&) {
  return std::make_unique<TraceContext>();
}

REGISTER_FACTORY(Factory, Envoy::Http::EarlyHeaderMutationFactory);

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation
