#pragma once

#include "envoy/upstream/health_check_event_sink.h"
#include "source/common/grpc/typed_async_client.h"

namespace Envoy::Upstream {

class GrpcHealthCheckEventSink : public HealthCheckEventSink,
                                 public Grpc::AsyncRequestCallbacks<Protobuf::Empty>,
                                 public Logger::Loggable<Logger::Id::health_checker> {
public:
  explicit GrpcHealthCheckEventSink(Grpc::RawAsyncClientSharedPtr client);

  void onSuccess(Grpc::ResponsePtr<Protobuf::Empty>&&, Tracing::Span&) override {}
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}

  void onFailure(Grpc::Status::GrpcStatus status, const std::string& message, Tracing::Span&) override;
  void log(envoy::data::core::v3::HealthCheckEvent event) override;

private:
  Grpc::AsyncClient<envoy::data::core::v3::HealthCheckEvent, Protobuf::Empty> client_;
  const Protobuf::MethodDescriptor& service_method_;
};

class GrpcHealthCheckEventSinkFactory : public HealthCheckEventSinkFactory {
public:
  GrpcHealthCheckEventSinkFactory() = default;

  HealthCheckEventSinkPtr
  createHealthCheckEventSink(const Protobuf::Any& config,
                             Server::Configuration::HealthCheckerFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override { return "envoy.health_check.event_sink.grpc"; }
};

} // namespace Envoy::Upstream