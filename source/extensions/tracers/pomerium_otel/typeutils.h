#pragma once

#include "envoy/config/trace/v3/opentelemetry.pb.h"
#include "envoy/config/trace/v3/opentelemetry.pb.validate.h"
#include "source/extensions/tracers/pomerium_otel/pomerium_otel.pb.h"

inline envoy::config::trace::v3::OpenTelemetryConfig
toBaseConfig(const ::pomerium::extensions::OpenTelemetryConfig& proto_config) {
  envoy::config::trace::v3::OpenTelemetryConfig base;
  if (proto_config.has_grpc_service()) {
    *base.mutable_grpc_service() = proto_config.grpc_service();
  }
  if (proto_config.has_http_service()) {
    *base.mutable_http_service() = proto_config.http_service();
  }
  base.set_service_name(proto_config.service_name());
  base.mutable_resource_detectors()->CopyFrom(proto_config.resource_detectors());
  if (proto_config.has_sampler()) {
    *base.mutable_sampler() = proto_config.sampler();
  }
  return base;
}

namespace pomerium::extensions {
inline bool Validate(const ::pomerium::extensions::OpenTelemetryConfig& m,
                     pgv::ValidationMsg* err) {
  return Validate(toBaseConfig(m), err);
}
} // namespace pomerium::extensions