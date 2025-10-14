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
#include "test/mocks/server/tracer_factory_context.h"

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

  tracing_span->setTag("foo", "bar");
  auto attr = dynamic_cast<OpenTelemetry::VariableNameSpan*>(tracing_span.get())->spanForTest().spanForTest().attributes().at(0);
  EXPECT_EQ("foo", attr.key());
  EXPECT_EQ("bar", attr.value().string_value());
  Event::SimulatedTimeSystem time_system;

  tracing_span->log(time_system.systemTime(), ""); // envoy doesn't implement this

  Tracing::TestTraceContextImpl request_headers{};

  tracing_span->injectContext(request_headers, Tracing::UpstreamContext());

  EXPECT_FALSE(request_headers.get("traceparent")->empty());

  EXPECT_NE(nullptr, tracing_span->spawnChild(config, "asdf", time_system.systemTime()));

  tracing_span->setBaggage("key", "val");
  EXPECT_EQ("", tracing_span->getBaggage("key")); // envoy doesn't implement this

  EXPECT_FALSE(tracing_span->getSpanId().empty());
  EXPECT_FALSE(tracing_span->useLocalDecision());

  EXPECT_EQ(static_cast<uint64_t>(0), dynamic_cast<OpenTelemetry::VariableNameSpan*>(tracing_span.get())->spanForTest().spanForTest().end_time_unix_nano());
  tracing_span->finishSpan();
  EXPECT_NE(static_cast<uint64_t>(0), dynamic_cast<OpenTelemetry::VariableNameSpan*>(tracing_span.get())->spanForTest().spanForTest().end_time_unix_nano());
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

TEST_F(PomeriumOtelTest, ToBaseConfig) {
  pomerium::extensions::OpenTelemetryConfig ours;
  envoy::config::trace::v3::OpenTelemetryConfig upstream;
  auto yaml_grpc = R"(
service_name: "test"
resource_detectors: []
grpc_service:
  envoy_grpc:
    cluster_name: fake-cluster
  timeout: 0.250s
service_name: my-service
sampler:
  name: envoy.tracers.opentelemetry.samplers.testsampler
  typed_config:
    "@type": type.googleapis.com/google.protobuf.Value
)";
  TestUtility::loadFromYamlAndValidate(yaml_grpc, ours);
  TestUtility::loadFromYamlAndValidate(yaml_grpc, upstream);
  EXPECT_EQ(ours.SerializeAsString(), upstream.SerializeAsString());

  auto yaml_http = R"(
service_name: "test"
resource_detectors: []
http_service:
  http_uri:
    uri: "https://some-o11y.com//otlp/v1/traces"
    cluster: "my_o11y_backend"
    timeout: 0.250s
service_name: my-service
sampler:
  name: envoy.tracers.opentelemetry.samplers.testsampler
  typed_config:
    "@type": type.googleapis.com/google.protobuf.Value
)";
  ours.Clear();
  upstream.Clear();
  TestUtility::loadFromYamlAndValidate(yaml_http, ours);
  TestUtility::loadFromYamlAndValidate(yaml_http, upstream);
  EXPECT_EQ(ours.SerializeAsString(), upstream.SerializeAsString());
}

TEST(FactoryTest, FactoryTest) {
  testing::NiceMock<Server::Configuration::MockTracerFactoryContext> context;

  auto* factory = Registry::FactoryRegistry<Server::Configuration::TracerFactory>::getFactory(
    "envoy.tracers.pomerium_otel");
  ASSERT_NE(factory, nullptr);

  pomerium::extensions::OpenTelemetryConfig cfg{};

  ASSERT_EQ("pomerium.extensions.OpenTelemetryConfig", factory->createEmptyConfigProto()->GetTypeName());

  EXPECT_NE(nullptr, factory->createTracerDriver(cfg, context));
}

} // namespace Envoy::Extensions::Tracers::OpenTelemetry
