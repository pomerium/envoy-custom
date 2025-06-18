#include "source/extensions/filters/network/ssh/config.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#pragma clang unsafe_buffer_usage end

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

std::shared_ptr<pomerium::extensions::ssh::CodecConfig> newTestConfig() {
  auto cfg = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
  for (auto keyName : {"rsa_1", "ed25519_1"}) {
    auto hostKeyFile = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    cfg->add_host_keys()->set_filename(hostKeyFile);
  }
  auto userCaKeyFile = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_2", 0600);
  cfg->mutable_user_ca_key()->set_filename(userCaKeyFile);
  cfg->mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name("test-cluster");
  return cfg;
}

TEST(FactoryTest, FactoryTest) {
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;

  auto* factoryConfig = Registry::FactoryRegistry<CodecFactoryConfig>::getFactory(
    "envoy.generic_proxy.codecs.ssh");
  ASSERT_NE(factoryConfig, nullptr);

  auto cfg = newTestConfig();

  ASSERT_EQ("pomerium.extensions.ssh.CodecConfig", factoryConfig->createEmptyConfigProto()->GetTypeName());

  auto factory = factoryConfig->createCodecFactory(*cfg, context);
  ASSERT_NE(nullptr, factory);
  auto serverCodec = factory->createServerCodec();
  ASSERT_NE(nullptr, serverCodec);
  auto clientCodec = factory->createClientCodec();
  ASSERT_NE(nullptr, clientCodec);
}

TEST(FactoryTest, FactoryTest_Error) {
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;

  auto* factoryConfig = Registry::FactoryRegistry<CodecFactoryConfig>::getFactory(
    "envoy.generic_proxy.codecs.ssh");
  ASSERT_NE(factoryConfig, nullptr);

  auto cfg = newTestConfig();

  EXPECT_CALL(context.cluster_manager_.async_client_manager_, factoryForGrpcService)
    .WillOnce(testing::InvokeWithoutArgs([] {
      return absl::InternalError("test error");
    }));
  auto factory = factoryConfig->createCodecFactory(*cfg, context);
  EXPECT_THROW_WITH_MESSAGE(factory->createServerCodec(),
                            EnvoyException,
                            "test error");
}

TEST(FactoryTest, ConfigValidation) {
  pomerium::extensions::ssh::CodecConfig cfg;
  EXPECT_NO_THROW(
    TestUtility::loadFromYamlAndValidate(
      R"(
    host_keys:
      - filename: /path/to/file1
      - filename: /path/to/file2
      - inline_string: test
      - inline_bytes: dGVzdAo=
    user_ca_key:
      filename: /path/to/key
    grpc_service:
      envoy_grpc:
        cluster_name: test
    )",
      cfg););

  EXPECT_THROW_WITH_REGEX(
    TestUtility::loadFromYamlAndValidate(
      R"(
    host_keys: []
    user_ca_key:
      filename: /path/to/key
    grpc_service:
      envoy_grpc:
        cluster_name: test
    )",
      cfg);
    , Envoy::ProtoValidationException,
    "CodecConfigValidationError.HostKeys: value must contain at least 1 item");

  EXPECT_THROW_WITH_REGEX(
    TestUtility::loadFromYamlAndValidate(
      R"(
    host_keys:
      - filename: /path/to/file1
      - filename: /path/to/file2
      - inline_string: test
      - inline_bytes: dGVzdAo=
    grpc_service:
      envoy_grpc:
        cluster_name: test
    )",
      cfg);
    , Envoy::ProtoValidationException,
    "CodecConfigValidationError.UserCaKey: value is required");

  EXPECT_THROW_WITH_REGEX(
    TestUtility::loadFromYamlAndValidate(
      R"(
    host_keys:
      - filename: /path/to/file1
      - filename: /path/to/file2
      - inline_string: test
      - inline_bytes: dGVzdAo=
    user_ca_key:
      filename: /path/to/key
    )",
      cfg);
    , Envoy::ProtoValidationException,
    "CodecConfigValidationError.GrpcService: value is required");
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec