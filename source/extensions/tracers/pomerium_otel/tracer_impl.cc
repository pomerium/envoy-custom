
#include "source/extensions/tracers/pomerium_otel/tracer_impl.h"

#include "source/extensions/tracers/pomerium_otel/span.h"
#include "source/common/tracing/trace_context_impl.h"
#include "source/common/common/logger.h"
#include "source/common/http/path_utility.h"

namespace Envoy::Extensions::Tracers::OpenTelemetry {

const Tracing::TraceContextHandler& pomeriumTraceParentHeader() {
  CONSTRUCT_ON_FIRST_USE(Tracing::TraceContextHandler, "x-pomerium-traceparent");
}

const Tracing::TraceContextHandler& pomeriumTraceIDHeader() {
  CONSTRUCT_ON_FIRST_USE(Tracing::TraceContextHandler, "x-pomerium-traceid");
}

const Tracing::TraceContextHandler& pomeriumSamplingDecisionHeader() {
  CONSTRUCT_ON_FIRST_USE(Tracing::TraceContextHandler, "x-pomerium-sampling-decision");
}

// workaround for OpenTelemetry::Driver having private inheritance to
// Logger::Loggable<Logger::Id::tracing>
static spdlog::logger& logger() {
  static spdlog::logger& instance = Envoy::Logger::Registry::getLog(Logger::Id::tracing);
  return instance;
}

Tracing::SpanPtr PomeriumDriver::startSpan(const Tracing::Config& config,
                                           Tracing::TraceContext& trace_context,
                                           const StreamInfo::StreamInfo& stream_info,
                                           const std::string& operation_name,
                                           Tracing::Decision tracing_decision) {

  std::vector<std::tuple<std::string, std::string>> name_substitutions{
      {"${path}", std::string(Envoy::Http::PathUtil::removeQueryAndFragment(trace_context.path()))},
      {"${host}", std::string(trace_context.host())},
      {"${method}", std::string(trace_context.method())},
      {"${protocol}", std::string(trace_context.protocol())},
  };
  auto span = new VariableNameSpan(
      Driver::startSpan(config, trace_context, stream_info, operation_name, tracing_decision),
      name_substitutions);

  if (auto tp = pomeriumTraceParentHeader().get(trace_context);
      tp.has_value() && tp->size() == 55) {
    auto new_trace_id = tp.value().substr(3, 32);
    ENVOY_LOG_TO_LOGGER(logger(), trace, "rewriting trace ID {} => {}", span->getTraceId(),
                        new_trace_id);
    span->setTraceId(new_trace_id);
  } else if (auto tid = pomeriumTraceIDHeader().get(trace_context);
             tid.has_value() && tid.value().size() == 32) {
    auto new_trace_id = tid.value();
    ENVOY_LOG_TO_LOGGER(logger(), trace, "rewriting trace ID (alt) {} => {}", span->getTraceId(),
                        new_trace_id);
    span->setTraceId(new_trace_id);
  }
  if (auto decision = pomeriumSamplingDecisionHeader().get(trace_context); decision.has_value()) {
    ENVOY_LOG_TO_LOGGER(logger(), trace, "forcing sampling decision: {}", decision.value());
    span->setSampled(decision.value() == "1");
  }

  return Tracing::SpanPtr(static_cast<Tracing::Span*>(span));
}

} // namespace Envoy::Extensions::Tracers::OpenTelemetry
