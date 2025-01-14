#pragma once

#include "api/extensions/request_id/uuidx/uuidx.pb.h"

#include "envoy/extensions/request_id/uuid/v3/uuid.pb.h"
#include "envoy/extensions/request_id/uuid/v3/uuid.pb.validate.h"
#include "source/extensions/request_id/uuid/config.h"

namespace Envoy::Extensions::RequestId {

using envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig;
using pomerium::extensions::UuidxRequestIdConfig;

class UUIDxRequestIDExtension : public UUIDRequestIDExtension {
public:
  using UUIDRequestIDExtension::UUIDRequestIDExtension;
  UUIDxRequestIDExtension(const UuidxRequestIdConfig& config, Random::RandomGenerator& random)
      : UUIDxRequestIDExtension(toBaseConfig(config), random) {}

  Tracing::Reason getTraceReason(const Envoy::Http::RequestHeaderMap& request_headers) override;
  void setTraceReason(Envoy::Http::RequestHeaderMap& request_headers,
                      Tracing::Reason reason) override;

private:
  absl::optional<Tracing::Reason>
  getInternalReason(const Envoy::Http::RequestHeaderMap& request_headers);

  static inline UuidRequestIdConfig toBaseConfig(const UuidxRequestIdConfig& config) {
    UuidRequestIdConfig base_config;
    if (config.has_pack_trace_reason()) {
      *base_config.mutable_pack_trace_reason() = config.pack_trace_reason();
    }
    if (config.has_use_request_id_for_trace_sampling()) {
      *base_config.mutable_use_request_id_for_trace_sampling() =
          config.use_request_id_for_trace_sampling();
    }
    return base_config;
  }

  Envoy::Http::LowerCaseString pomerium_sampling_decision_header{"x-pomerium-sampling-decision"};
};

DECLARE_FACTORY(UUIDxRequestIDExtensionFactory);

} // namespace Envoy::Extensions::RequestId