#pragma once

#include "source/extensions/tracers/pomerium_otel/pomerium_otel.pb.h"
#include "source/extensions/tracers/pomerium_otel/typeutils.h"

#include "source/extensions/tracers/common/factory_base.h"

namespace Envoy::Extensions::Tracers::OpenTelemetry {

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

} // namespace Envoy::Extensions::Tracers::OpenTelemetry
