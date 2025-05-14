#include "source/extensions/request_id/uuidx/config.h"

#include "source/common/common/random_generator.h"
#include "test/test_common/utility.h"
#include "test/mocks/server/factory_context.h"

#include "gtest/gtest.h"

namespace Envoy::Extensions::RequestId {

TEST(UUIDxRequestIDExtensionTest, SamplingDecisionHeader) {
  Random::RandomGeneratorImpl random;
  UUIDxRequestIDExtension ext(pomerium::extensions::UuidxRequestIdConfig(), random);
  {
    Http::TestRequestHeaderMapImpl request_headers{};
    request_headers.setRequestId(random.uuid());
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));
  }
  {
    Http::TestRequestHeaderMapImpl request_headers{{"x-pomerium-sampling-decision", "1"}};
    request_headers.setRequestId(random.uuid());
    EXPECT_EQ(Tracing::Reason::ServiceForced, ext.getTraceReason(request_headers));
    EXPECT_EQ('4', request_headers.getRequestIdValue()[14]);
  }
  {
    Http::TestRequestHeaderMapImpl request_headers{{"x-pomerium-sampling-decision", "0"}};
    auto id = random.uuid();
    id[14] = '9';
    request_headers.setRequestId(id);
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));
    EXPECT_EQ('9', request_headers.getRequestIdValue()[14]);
  }
  {
    Http::TestRequestHeaderMapImpl request_headers{{"x-pomerium-sampling-decision", "0"}};
    request_headers.setRequestId(random.uuid());
    EXPECT_EQ('4', request_headers.getRequestIdValue()[14]); // 4 = not sampled
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));

    ext.setTraceReason(request_headers, Tracing::Reason::Sampling);
    EXPECT_EQ('4', request_headers.getRequestIdValue()[14]);
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));

    ext.setTraceReason(request_headers, Tracing::Reason::ServiceForced);
    EXPECT_EQ('4', request_headers.getRequestIdValue()[14]);
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));

    ext.setTraceReason(request_headers, Tracing::Reason::ClientForced);
    EXPECT_EQ('4', request_headers.getRequestIdValue()[14]);
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));
  }
  {
    Http::TestRequestHeaderMapImpl request_headers{};
    request_headers.setRequestId(random.uuid());
    EXPECT_EQ('4', request_headers.getRequestIdValue()[14]); // 4 = not sampled
    EXPECT_EQ(Tracing::Reason::NotTraceable, ext.getTraceReason(request_headers));

    ext.setTraceReason(request_headers, Tracing::Reason::Sampling);
    EXPECT_EQ('9', request_headers.getRequestIdValue()[14]);
    EXPECT_EQ(Tracing::Reason::Sampling, ext.getTraceReason(request_headers));

    ext.setTraceReason(request_headers, Tracing::Reason::ServiceForced);
    EXPECT_EQ('a', request_headers.getRequestIdValue()[14]);
    EXPECT_EQ(Tracing::Reason::ServiceForced, ext.getTraceReason(request_headers));

    ext.setTraceReason(request_headers, Tracing::Reason::ClientForced);
    EXPECT_EQ('b', request_headers.getRequestIdValue()[14]);
    EXPECT_EQ(Tracing::Reason::ClientForced, ext.getTraceReason(request_headers));
  }
}

TEST(FactoryTest, FactoryTest) {
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;

  auto* factory = Registry::FactoryRegistry<Server::Configuration::RequestIDExtensionFactory>::getFactory(
    "envoy.request_id.uuidx");
  ASSERT_NE(factory, nullptr);

  pomerium::extensions::UuidxRequestIdConfig cfg{};
  cfg.mutable_pack_trace_reason()->set_value(true);
  cfg.mutable_use_request_id_for_trace_sampling()->set_value(true);

  ASSERT_EQ("pomerium.extensions.UuidxRequestIdConfig", factory->createEmptyConfigProto()->GetTypeName());

  EXPECT_NE(nullptr, factory->createExtensionInstance(cfg, context));
}

} // namespace Envoy::Extensions::RequestId