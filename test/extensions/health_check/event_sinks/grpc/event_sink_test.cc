#include "api/extensions/health_check/event_sinks/grpc/event_sink.pb.h"
#include "api/extensions/health_check/event_sinks/grpc/event_sink.pb.validate.h"
#include "source/extensions/health_check/event_sinks/grpc/event_sink.h"
#include "test/mocks/server/health_checker_factory_context.h"
#include "test/test_common/proto_equal.h"
#include "test/test_common/utility.h"
#include "envoy/upstream/health_check_event_sink.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy::Upstream {
namespace test {

TEST(GrpcHealthCheckEventSinkFactory, CreateHealthCheckEventSink) {
  auto factory = Envoy::Registry::FactoryRegistry<Envoy::Upstream::HealthCheckEventSinkFactory>::getFactory(
    "envoy.health_check.event_sink.grpc");
  EXPECT_NE(factory, nullptr);

  envoy::extensions::health_check::event_sinks::grpc::Config config;
  *config.mutable_grpc_service()->mutable_envoy_grpc()->mutable_cluster_name() = "test";
  Envoy::Protobuf::Any typed_config;
  typed_config.PackFrom(config);

  NiceMock<Server::Configuration::MockHealthCheckerFactoryContext> context;
  EXPECT_NE(factory->createHealthCheckEventSink(typed_config, context), nullptr);
}

TEST(GrpcHealthCheckEventSinkFactory, CreateEmptyConfigProto) {
  auto factory = Envoy::Registry::FactoryRegistry<Envoy::Upstream::HealthCheckEventSinkFactory>::getFactory(
    "envoy.health_check.event_sink.grpc");
  EXPECT_NE(factory, nullptr);
  envoy::extensions::health_check::event_sinks::grpc::Config cfg;
  ASSERT_THAT(*factory->createEmptyConfigProto(), ProtoEq(cfg));
}

TEST(GrpcHealthCheckEventSink, Log) {
  auto async_client = std::make_shared<Grpc::MockAsyncClient>();
  envoy::data::core::v3::HealthCheckEvent event;
  event.set_cluster_name("foo");
  event.mutable_successful_health_check_event();
  GrpcHealthCheckEventSink sink(async_client);
  EXPECT_CALL(*async_client, sendRaw(_, _, ProtoBufferStrictEq(event), _, _, _));
  sink.log(event);
}

TEST(GrpcHealthCheckEventSink, AsyncCallbacks) {
  auto async_client = std::make_shared<Grpc::MockAsyncClient>();
  GrpcHealthCheckEventSink sink(async_client);
  // the async request callbacks are no-ops
  Http::TestRequestHeaderMapImpl headers;
  sink.onCreateInitialMetadata(headers);
  sink.onSuccess(nullptr, Tracing::NullSpan::instance());
  sink.onFailure(Grpc::Status::Internal, "test error", Tracing::NullSpan::instance());
}

} // namespace test
} // namespace Envoy::Upstream