#include "source/extensions/tracers/pomerium_otel/config.h"

#include "envoy/registry/registry.h"
#include "source/extensions/tracers/pomerium_otel/tracer_impl.h"

// #ifndef ENVOY_ENABLE_UHV
// #warning "uhv not enabled"
// #endif
namespace Envoy::Extensions::Tracers::OpenTelemetry {

PomeriumOpenTelemetryTracerFactory::PomeriumOpenTelemetryTracerFactory()
    : FactoryBase("envoy.tracers.pomerium_otel") {}

Tracing::DriverSharedPtr PomeriumOpenTelemetryTracerFactory::createTracerDriverTyped(
    const pomerium::extensions::OpenTelemetryConfig& proto_config,
    Server::Configuration::TracerFactoryContext& context) {
  return std::make_shared<PomeriumDriver>(toBaseConfig(proto_config), context);
}

REGISTER_FACTORY(PomeriumOpenTelemetryTracerFactory, Server::Configuration::TracerFactory);

} // namespace Envoy::Extensions::Tracers::OpenTelemetry
