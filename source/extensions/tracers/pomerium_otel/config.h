#pragma once

#include <string>

#include "source/extensions/tracers/pomerium_otel/typeutils.h"

#include "envoy/config/trace/v3/opentelemetry.pb.h"
#include "envoy/config/trace/v3/opentelemetry.pb.validate.h"
#include "source/extensions/tracers/pomerium_otel/pomerium_otel.pb.h"

#include "source/extensions/tracers/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace Tracers {
namespace OpenTelemetry {

/**
 * Config registration for the OpenTelemetry tracer. @see TracerFactory.
 */
class PomeriumOpenTelemetryTracerFactory
    : Logger::Loggable<Logger::Id::tracing>,
      public Common::FactoryBase<pomerium::extensions::OpenTelemetryConfig> {
public:
  PomeriumOpenTelemetryTracerFactory();

private:
  // FactoryBase
  Tracing::DriverSharedPtr
  createTracerDriverTyped(const pomerium::extensions::OpenTelemetryConfig& proto_config,
                          Server::Configuration::TracerFactoryContext& context) override;
};

} // namespace OpenTelemetry
} // namespace Tracers
} // namespace Extensions
} // namespace Envoy
