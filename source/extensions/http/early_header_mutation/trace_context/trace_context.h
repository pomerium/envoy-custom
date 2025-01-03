#pragma once

#include "envoy/http/early_header_mutation.h"
#include "source/extensions/http/early_header_mutation/trace_context/trace_context.pb.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

constexpr auto pomerium_traceparent_query = "pomerium_traceparent";
constexpr auto pomerium_tracestate_query = "pomerium_tracestate";

class TraceContext : public Envoy::Http::EarlyHeaderMutation,
                     public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  TraceContext() = default;

  bool mutate(Envoy::Http::RequestHeaderMap& headers,
              const Envoy::StreamInfo::StreamInfo& stream_info) const override;

private:
  Envoy::Http::LowerCaseString pomerium_sampling_decision_header{"x-pomerium-sampling-decision"};
  Envoy::Http::LowerCaseString pomerium_traceparent_header{"x-pomerium-traceparent"};
  Envoy::Http::LowerCaseString pomerium_tracestate_header{"x-pomerium-tracestate"};
  Envoy::Http::LowerCaseString pomerium_external_parent_header{"x-pomerium-external-parent-span"};
  Envoy::Http::LowerCaseString traceparent_header{"traceparent"};
};

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation