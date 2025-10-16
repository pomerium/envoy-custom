#include "source/extensions/http/early_header_mutation/trace_context/config.h"

#include "test/mocks/server/factory_context.h"

#include "api/extensions/http/early_header_mutation/trace_context/trace_context.pb.h"

#include "gtest/gtest.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

TEST(FactoryTest, FactoryTest) {
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;

  auto* factory = Registry::FactoryRegistry<Envoy::Http::EarlyHeaderMutationFactory>::getFactory(
    "envoy.http.early_header_mutation.trace_context");
  ASSERT_NE(factory, nullptr);

  pomerium::extensions::TraceContext cfg{};

  ASSERT_EQ("pomerium.extensions.TraceContext", factory->createEmptyConfigProto()->GetTypeName());

  Protobuf::Any any_config;
  any_config.PackFrom(cfg);

  EXPECT_NE(nullptr, factory->createExtension(any_config, context));
}

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation