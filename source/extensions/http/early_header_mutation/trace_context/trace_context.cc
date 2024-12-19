#include "source/extensions/http/early_header_mutation/trace_context/trace_context.h"
#include "source/common/common/logger.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

constexpr auto pomerium_traceparent_query = "pomerium_traceparent";
constexpr auto pomerium_trace_decision = "x-pomerium-internal-trace-decision";

bool TraceContext::mutate(Envoy::Http::RequestHeaderMap& headers,
                          const Envoy::StreamInfo::StreamInfo&) const {
  static const auto trace_decision_header = Envoy::Http::LowerCaseString(pomerium_trace_decision);
  headers.remove(trace_decision_header); // remove the header if it is set externally

  auto params =
      Envoy::Http::Utility::QueryParamsMulti::parseAndDecodeQueryString(headers.getPathValue());

  auto pomerium_traceparent = params.getFirstValue(pomerium_traceparent_query);
  if (!pomerium_traceparent.has_value()) {
    return true;
  }

  auto&& traceparent = pomerium_traceparent.value();
  auto segments = std::vector<std::string>(absl::StrSplit(traceparent, '-', absl::SkipEmpty()));
  if (segments.size() != 4) {
    return true;
  }

  auto flags_hex = segments[3];
  if (flags_hex.size() != 2 || !absl::ascii_isxdigit(flags_hex[0]) ||
      !absl::ascii_isxdigit(flags_hex[1])) {
    return true;
  }

  auto flags = absl::HexStringToBytes(flags_hex).front();
  if (flags & 1) { // sampled
    headers.setCopy(trace_decision_header, "1");
    ENVOY_LOG(debug, "pomerium_traceparent={}, forcing trace decision (on)", traceparent);
  } else { // not sampled
    headers.setCopy(trace_decision_header, "0");
    ENVOY_LOG(debug, "pomerium_traceparent={}, forcing sampling decision (off)", traceparent);
  }

  return true;
}

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation