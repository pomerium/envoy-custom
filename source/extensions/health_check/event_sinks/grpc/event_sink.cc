#include "api/extensions/health_check/event_sinks/grpc/event_sink.pb.h"
#include "api/extensions/health_check/event_sinks/grpc/event_sink.pb.validate.h"
#include "source/extensions/health_check/event_sinks/grpc/event_sink.h"
#include "source/common/grpc/status.h"

namespace Envoy::Upstream {

GrpcHealthCheckEventSink::GrpcHealthCheckEventSink(Grpc::RawAsyncClientSharedPtr client)
    : client_(std::move(client)),
      service_method_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
        "envoy.extensions.health_check.event_sinks.grpc.HealthCheckEventSink.LogHealthCheckEvent")) {
}

void GrpcHealthCheckEventSink::onFailure(Grpc::Status::GrpcStatus status, const std::string& message, Tracing::Span&) {
  ENVOY_LOG(warn, "error sending health check event: {}: {}",
            Grpc::Utility::grpcStatusToString(status), message);
}

void GrpcHealthCheckEventSink::log(envoy::data::core::v3::HealthCheckEvent event) {
  client_.send(service_method_, event, *this, Tracing::NullSpan::instance(), Http::AsyncClient::RequestOptions{});
}

HealthCheckEventSinkPtr
GrpcHealthCheckEventSinkFactory::createHealthCheckEventSink(const Protobuf::Any& config,
                                                            Server::Configuration::HealthCheckerFactoryContext& context) {
  auto typedConfig = MessageUtil::anyConvertAndValidate<envoy::extensions::health_check::event_sinks::grpc::Config>(
    config, context.messageValidationVisitor());

  auto grpcClient =
    context.serverFactoryContext()
      .clusterManager()
      .grpcAsyncClientManager()
      .getOrCreateRawAsyncClient(typedConfig.grpc_service(), context.serverFactoryContext().scope(), false);
  THROW_IF_NOT_OK_REF(grpcClient.status());

  return std::make_unique<GrpcHealthCheckEventSink>(std::move(grpcClient).value());
}

ProtobufTypes::MessagePtr GrpcHealthCheckEventSinkFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::health_check::event_sinks::grpc::Config>();
}

REGISTER_FACTORY(GrpcHealthCheckEventSinkFactory, HealthCheckEventSinkFactory);

} // namespace Envoy::Upstream