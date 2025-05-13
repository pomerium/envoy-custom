#include "source/extensions/tracers/pomerium_otel/config.h"
#include "source/extensions/tracers/pomerium_otel/span.h"

#include "source/common/tracing/http_tracer_impl.h"
#include "test/mocks/server/tracer_factory_context.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/mocks/thread_local/mocks.h"
#include "test/mocks/tracing/mocks.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/utility.h"
#include "source/extensions/tracers/pomerium_otel/tracer_impl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

constexpr std::string_view example_traceid =
  "00-11111111111111111111111111111111-2222222222222222-01";

namespace Envoy::Extensions::Tracers::OpenTelemetry {

using testing::Return;

class PomeriumOtelTest : public testing::Test {
public:
  PomeriumOtelTest();

protected:
  NiceMock<Tracing::MockConfig> config;
  NiceMock<StreamInfo::MockStreamInfo> stream_info;
  NiceMock<Server::Configuration::MockTracerFactoryContext> context;
  NiceMock<Upstream::MockClusterManager> cluster_manager_;

  Tracing::TestTraceContextImpl trace_context{};
  std::unique_ptr<PomeriumDriver> driver;
};

PomeriumOtelTest::PomeriumOtelTest() {
  cluster_manager_.initializeClusters({"fake-cluster"}, {});
  cluster_manager_.thread_local_cluster_.cluster_.info_->name_ = "fake-cluster";
  cluster_manager_.initializeThreadLocalClusters({"fake-cluster"});

  const std::string yaml_string = R"EOF(
    grpc_service:
      envoy_grpc:
        cluster_name: fake-cluster
      timeout: 0.250s
    service_name: test-service-name
    )EOF";

  envoy::config::trace::v3::OpenTelemetryConfig opentelemetry_config;
  TestUtility::loadFromYaml(yaml_string, opentelemetry_config);

  trace_context = {
    {":method", "GET"},
    {":protocol", "https://"},
    {":authority", "foo.example.com"},
    {":path", "/bar"},
  };
  driver = std::make_unique<PomeriumDriver>(opentelemetry_config, context);
}

TEST_F(PomeriumOtelTest, VariableNameSpan) {
  const std::string operation_name = "overwritten";
  Tracing::SpanPtr tracing_span = driver->startSpan(
    config, trace_context, stream_info, operation_name, {Tracing::Reason::Sampling, true});

  EXPECT_EQ(dynamic_cast<VariableNameSpan*>(tracing_span.get())->name(), operation_name);

  const std::string new_operation_name = "${method} ${protocol}${host}${path}";
  tracing_span->setOperation(new_operation_name);
  EXPECT_EQ(dynamic_cast<VariableNameSpan*>(tracing_span.get())->name(),
            "GET https://foo.example.com/bar");
}

TEST_F(PomeriumOtelTest, StartSpanWithNoTraceparent) {
  NiceMock<Random::MockRandomGenerator>& mock_random_generator_ =
    context.server_factory_context_.api_.random_;
  ON_CALL(mock_random_generator_, random()).WillByDefault(Return(0xDEADBEEFDEADBEEF));

  Tracing::SpanPtr tracing_span = driver->startSpan(config, trace_context, stream_info, "test",
                                                    {Tracing::Reason::Sampling, true});

  EXPECT_EQ(tracing_span->getTraceId(), absl::StrCat(Hex::uint64ToHex(0xDEADBEEFDEADBEEF),
                                                     Hex::uint64ToHex(0xDEADBEEFDEADBEEF)));
}

TEST_F(PomeriumOtelTest, StartSpanWithTraceparent) {
  NiceMock<Random::MockRandomGenerator>& mock_random_generator_ =
    context.server_factory_context_.api_.random_;
  ON_CALL(mock_random_generator_, random()).WillByDefault(Return(0xDEADBEEFDEADBEEF));

  trace_context.set("x-pomerium-traceparent", example_traceid);
  Tracing::SpanPtr tracing_span = driver->startSpan(config, trace_context, stream_info, "test",
                                                    {Tracing::Reason::Sampling, true});
  EXPECT_EQ(tracing_span->getTraceId(), example_traceid.substr(3, 32));
}

TEST_F(PomeriumOtelTest, StartSpanWithTraceID) {
  NiceMock<Random::MockRandomGenerator>& mock_random_generator_ =
    context.server_factory_context_.api_.random_;
  ON_CALL(mock_random_generator_, random()).WillByDefault(Return(0xDEADBEEFDEADBEEF));

  trace_context.set("x-pomerium-traceid", example_traceid.substr(3, 32));
  Tracing::SpanPtr tracing_span = driver->startSpan(config, trace_context, stream_info, "test",
                                                    {Tracing::Reason::Sampling, true});
  EXPECT_EQ(tracing_span->getTraceId(), example_traceid.substr(3, 32));
}

TEST_F(PomeriumOtelTest, StartSpanWithSamplingDecisionOff) {
  trace_context.set("x-pomerium-sampling-decision", "0");
  Tracing::SpanPtr tracing_span = driver->startSpan(config, trace_context, stream_info, "test",
                                                    {Tracing::Reason::Sampling, true});
  EXPECT_FALSE(dynamic_cast<VariableNameSpan*>(tracing_span.get())->sampled());
}

TEST_F(PomeriumOtelTest, StartSpanWithSamplingDecisionOn) {
  trace_context.set("x-pomerium-sampling-decision", "1");
  Tracing::SpanPtr tracing_span = driver->startSpan(config, trace_context, stream_info, "test",
                                                    {Tracing::Reason::NotTraceable, false});
  EXPECT_TRUE(dynamic_cast<VariableNameSpan*>(tracing_span.get())->sampled());
}

} // namespace Envoy::Extensions::Tracers::OpenTelemetry
