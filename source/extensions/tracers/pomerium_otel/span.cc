#include "source/extensions/tracers/pomerium_otel/span.h"
#include "absl/strings/str_replace.h"
#include "source/common/common/assert.h"

namespace Envoy::Extensions::Tracers::OpenTelemetry {

VariableNameSpan::VariableNameSpan(Tracing::SpanPtr&& base, StrSubstitutions substitutions)
    : span_(dynamic_cast<BaseOtelSpan*>(base.release())), substitutions_(substitutions) {
  RELEASE_ASSERT(!!span_, "bug: span type is not OpenTelemetry::Span*");
}

void VariableNameSpan::setTraceId(const absl::string_view& trace_id_hex) {
  span_->setTraceId(trace_id_hex);
}

void VariableNameSpan::setOperation(absl::string_view operation_name) {
  span_->setOperation(absl::StrReplaceAll(operation_name, substitutions_));
}

void VariableNameSpan::setTag(absl::string_view name, absl::string_view value) {
  span_->setTag(name, value);
};

void VariableNameSpan::log(SystemTime timestamp, const std::string& event) {
  span_->log(timestamp, event);
};

void VariableNameSpan::finishSpan() { span_->finishSpan(); }

void VariableNameSpan::injectContext(Envoy::Tracing::TraceContext& trace_context,
                                     const Tracing::UpstreamContext& upstream) {
  span_->injectContext(trace_context, upstream);
}

Tracing::SpanPtr VariableNameSpan::spawnChild(const Tracing::Config& config,
                                              const std::string& name, SystemTime start_time) {
  return span_->spawnChild(config, name, start_time);
}

void VariableNameSpan::setSampled(bool sampled) { span_->setSampled(sampled); };

std::string VariableNameSpan::getBaggage(absl::string_view key) { return span_->getBaggage(key); };

void VariableNameSpan::setBaggage(absl::string_view key, absl::string_view value) {
  span_->setBaggage(key, value);
};

std::string VariableNameSpan::getTraceId() const { return span_->getTraceId(); }

std::string VariableNameSpan::getSpanId() const { return span_->getSpanId(); }

} // namespace Envoy::Extensions::Tracers::OpenTelemetry
