#pragma once

#include "envoy/tracing/trace_driver.h"
#include "source/extensions/tracers/opentelemetry/opentelemetry_tracer_impl.h"

namespace Envoy {
namespace Extensions {
namespace Tracers {
namespace OpenTelemetry {

/**
 * OpenTelemetry tracing driver.
 */
class PomeriumDriver : public Driver {
public:
  using Driver::Driver;

  // Tracing::Driver
  Tracing::SpanPtr startSpan(const Tracing::Config& config, Tracing::TraceContext& trace_context,
                             const StreamInfo::StreamInfo& stream_info,
                             const std::string& operation_name,
                             Tracing::Decision tracing_decision) override;

private:
};

} // namespace OpenTelemetry
} // namespace Tracers
} // namespace Extensions
} // namespace Envoy
