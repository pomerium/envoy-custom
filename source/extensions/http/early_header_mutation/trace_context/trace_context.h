#pragma once

#include "envoy/http/early_header_mutation.h"
#include "source/extensions/http/early_header_mutation/trace_context/trace_context.pb.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

class TraceContext : public Envoy::Http::EarlyHeaderMutation,
                     public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  TraceContext() = default;

  bool mutate(Envoy::Http::RequestHeaderMap& headers,
              const Envoy::StreamInfo::StreamInfo& stream_info) const override;

private:
};

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation