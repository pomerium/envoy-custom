#include "source/extensions/http/early_header_mutation/trace_context/trace_context.h"
#include "source/common/common/logger.h"
#include "source/common/common/base64.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

bool TraceContext::mutate(Envoy::Http::RequestHeaderMap& headers,
                          const Envoy::StreamInfo::StreamInfo&) const {
  /**
   * NB: Sampling
   * ------------
   * The goal here is to ensure a consistent sampling decision across multiple
   * redirects within a single logical request. The decision made on the client's
   * initial request (to envoy) should carry forward through redirects, even
   * though those subsequent requests are completely separate from envoy's
   * point of view; they carry separate request IDs, separate trace IDs (until
   * they are joined by pomerium), and - crucially - separate trace decisions.
   * On each new request, envoy will decide whether or not to sample it, and
   * that decision will be encoded into the traceparent header of the request.
   *
   * The sampled bit (0x1) of the flags segment (4th) contains the sampling
   * decision made by envoy. If there is an x-pomerium-traceparent header
   * present, it will encode the original sampling decision in the same place.
   *
   * If the x-pomerium-traceparent header is present, the sampling decision will
   * be set in the x-pomerium-sampling-decision header. This header is then read
   * by the uuidx extension to force the desired trace decision if necessary.
   */

  headers.remove(pomerium_external_parent_header);
  headers.remove(pomerium_sampling_decision_header);
  const auto params =
      Envoy::Http::Utility::QueryParamsMulti::parseAndDecodeQueryString(headers.getPathValue());

  const auto pomerium_traceparent = params.getFirstValue(pomerium_traceparent_query);
  if (!pomerium_traceparent.has_value()) {
    if (const auto& values = headers.get(traceparent_header); !values.empty()) {
      if (auto traceparent = values[0]->value().getStringView(); traceparent.size() == 55) {
        headers.setCopy(pomerium_external_parent_header, traceparent.substr(36, 16));
      }
    } else if (headers.getPathValue().starts_with("/oauth2/callback")) {
      // oauth2 callback is a special case, we can't encode the traceparent in the usual way since
      // the query parameters are standard and managed by oauth2 clients
      const auto state = params.getFirstValue(Envoy::Http::LowerCaseString("state"));
      if (state.has_value()) {
        const std::string stateDecoded =
            Base64Url::decode(StringUtil::removeTrailingCharacters(state.value(), '='));
        const std::vector<absl::string_view> segments =
            absl::StrSplit(stateDecoded, absl::MaxSplits('|', 3));
        if (segments.size() == 4) {
          const auto traceidDecoded = Base64Url::decode(segments[2]);
          if (traceidDecoded.size() == 17) { // 16 byte trace ID + 1 byte flags
            const auto traceID = traceidDecoded.substr(0, 16);
            const auto flags = traceidDecoded.at(16);
            headers.setCopy(pomerium_traceid_header, absl::BytesToHexString(traceID));
            headers.setCopy(pomerium_sampling_decision_header, (flags & 1) == 1 ? "1" : "0");
          }
        }
      }
    }

    return true;
  }

  const std::vector<absl::string_view> segments =
      absl::StrSplit(pomerium_traceparent.value(), '-', absl::SkipEmpty());
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
    headers.setCopy(pomerium_sampling_decision_header, "1");
  } else { // not sampled
    headers.setCopy(pomerium_sampling_decision_header, "0");
  }

  headers.setCopy(pomerium_traceparent_header, pomerium_traceparent.value());
  const auto pomerium_tracestate = params.getFirstValue(pomerium_tracestate_query);
  if (pomerium_tracestate.has_value()) {
    headers.setCopy(pomerium_tracestate_header, pomerium_tracestate.value());
  }

  return true;
}

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation