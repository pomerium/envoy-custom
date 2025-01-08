#include "source/extensions/tracers/pomerium_otel/config.h"

#include "envoy/config/trace/v3/opentelemetry.pb.h"
#include "envoy/config/trace/v3/opentelemetry.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/common/logger.h"
#include "source/extensions/tracers/pomerium_otel/tracer_impl.h"

namespace Envoy {
namespace Extensions {
namespace Tracers {
namespace OpenTelemetry {

PomeriumOpenTelemetryTracerFactory::PomeriumOpenTelemetryTracerFactory()
    : FactoryBase("envoy.tracers.pomerium_otel") {}

Tracing::DriverSharedPtr PomeriumOpenTelemetryTracerFactory::createTracerDriverTyped(
    const pomerium::extensions::OpenTelemetryConfig& proto_config,
    Server::Configuration::TracerFactoryContext& context) {
  envoy::config::trace::v3::OpenTelemetryConfig base = toBaseConfig(proto_config);
  return std::make_shared<PomeriumDriver>(base, context);
}

/**
 * Static registration for the OpenTelemetry tracer. @see RegisterFactory.
 */
REGISTER_FACTORY(PomeriumOpenTelemetryTracerFactory, Server::Configuration::TracerFactory);

} // namespace OpenTelemetry
} // namespace Tracers
} // namespace Extensions
} // namespace Envoy
