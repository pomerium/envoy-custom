#pragma once
#include "envoy/tracing/trace_driver.h"
#include "source/extensions/tracers/opentelemetry/opentelemetry_tracer_impl.h"

namespace Envoy::Extensions::Tracers::OpenTelemetry {

using BaseOtelSpan = ::Envoy::Extensions::Tracers::OpenTelemetry::Span;
using BaseOtelSpanPtr = std::unique_ptr<BaseOtelSpan>;
using StrSubstitutions = std::vector<std::tuple<std::string, std::string>>;

class VariableNameSpan : public Tracing::Span {
public:
  VariableNameSpan(Tracing::SpanPtr&& base, StrSubstitutions substitutions);
  ~VariableNameSpan() override = default;

  void setTraceId(const absl::string_view& trace_id_hex);
  std::string name() const;
  bool sampled() const;

  void setOperation(absl::string_view operation_name) override;

  void setTag(absl::string_view name, absl::string_view value) override;
  void log(SystemTime timestamp, const std::string& event) override;
  void finishSpan() override;
  void injectContext(Envoy::Tracing::TraceContext& trace_context,
                     const Tracing::UpstreamContext& upstream) override;
  Tracing::SpanPtr spawnChild(const Tracing::Config& config, const std::string& name,
                              SystemTime start_time) override;
  void setSampled(bool sampled) override;
  std::string getBaggage(absl::string_view key) override;
  void setBaggage(absl::string_view key, absl::string_view value) override;
  std::string getTraceId() const override;
  std::string getSpanId() const override;

  BaseOtelSpan& spanForTest() const;

private:
  BaseOtelSpanPtr span_;
  StrSubstitutions substitutions_;
};

} // namespace Envoy::Extensions::Tracers::OpenTelemetry