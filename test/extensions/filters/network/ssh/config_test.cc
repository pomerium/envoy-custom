#include "source/extensions/filters/network/ssh/config.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/test_common/test_common.h"
#include "test/test_common/registry.h"

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "api/extensions/filters/network/ssh/ssh.pb.validate.h"
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
  ASSERT_EQ(2, dynamic_cast<SshCodecFactory&>(*factory).hostKeys().size());
  ASSERT_NE(nullptr, dynamic_cast<SshCodecFactory&>(*factory).userCaKey());
}

TEST(FactoryTest, Error) {
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

TEST(FactoryTest, ErrorLoadingHostKeys) {
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;

  auto* factoryConfig = Registry::FactoryRegistry<CodecFactoryConfig>::getFactory(
    "envoy.generic_proxy.codecs.ssh");
  ASSERT_NE(factoryConfig, nullptr);

  auto cfg = newTestConfig();
  *(cfg->mutable_host_keys()->at(0).mutable_filename()) = "/nonexistent";
  EXPECT_THROW_WITH_MESSAGE(factoryConfig->createCodecFactory(*cfg, context),
                            EnvoyException,
                            "Not Found: error loading ssh host key [1/2] from file /nonexistent: No such file or directory");
}

TEST(FactoryTest, ErrorLoadingUserCaKey) {
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;

  auto* factoryConfig = Registry::FactoryRegistry<CodecFactoryConfig>::getFactory(
    "envoy.generic_proxy.codecs.ssh");
  ASSERT_NE(factoryConfig, nullptr);

  auto cfg = newTestConfig();
  *cfg->mutable_user_ca_key()->mutable_filename() = "/nonexistent";
  EXPECT_THROW_WITH_MESSAGE(factoryConfig->createCodecFactory(*cfg, context),
                            EnvoyException,
                            "Not Found: error loading ssh user ca key from file /nonexistent: No such file or directory");
}

TEST(FactoryTest, InvalidNonexistentChannelFilterFactory) {
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;

  auto* factoryConfig = Registry::FactoryRegistry<CodecFactoryConfig>::getFactory(
    "envoy.generic_proxy.codecs.ssh");
  ASSERT_NE(factoryConfig, nullptr);

  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();
  f->set_name("nonexistent");
  f->mutable_typed_config()->set_type_url("type.googleapis.com/google.protobuf.Int32Value");

  EXPECT_THROW_WITH_REGEX(factoryConfig->createCodecFactory(*cfg, context),
                          EnvoyException,
                          "no registered channel filter factory found for name: 'nonexistent'");
}

class ChannelFilterFactoryConfigTest : public testing::Test {
public:
  void SetUp() {
    factoryConfig = Registry::FactoryRegistry<CodecFactoryConfig>::getFactory(
      "envoy.generic_proxy.codecs.ssh");
    ASSERT_NE(factoryConfig, nullptr);

    ON_CALL(factory, createEmptyConfigProto).WillByDefault([] {
      // using some type that has validation rules
      return std::make_unique<envoy::config::core::v3::DataSource>();
    });
    ON_CALL(factory, name).WillByDefault(Return("test_channel_filter"));

    inject_ = std::make_unique<Registry::InjectFactory<ChannelFilterFactoryConfig>>(factory);
  }

  Envoy::Extensions::NetworkFilters::GenericProxy::CodecFactoryConfig* factoryConfig{};
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context;
  testing::NiceMock<MockChannelFilterFactoryConfig> factory;

private:
  std::unique_ptr<Registry::InjectFactory<ChannelFilterFactoryConfig>> inject_;
};

TEST_F(ChannelFilterFactoryConfigTest, Invalid_MissingTypedConfig) {
  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();
  f->set_name("test_channel_filter");

  // this validation should happen before our own validation logic is run
  EXPECT_THROW_WITH_REGEX(factoryConfig->createCodecFactory(*cfg, context),
                          EnvoyException,
                          "TypedExtensionConfigValidationError.TypedConfig: value is required");
}

TEST_F(ChannelFilterFactoryConfigTest, Invalid_WrongType) {
  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();
  f->set_name("test_channel_filter");
  google::protobuf::Int32Value v;
  v.set_value(1);
  f->mutable_typed_config()->PackFrom(v);
  // this should reach our validation logic
  EXPECT_THROW_WITH_REGEX(factoryConfig->createCodecFactory(*cfg, context),
                          EnvoyException,
                          "Unable to unpack as envoy.config.core.v3.DataSource");
}

TEST_F(ChannelFilterFactoryConfigTest, Valid) {
  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();
  f->set_name("test_channel_filter");
  envoy::config::core::v3::DataSource v;
  v.set_filename("test"); // will satisfy protovalidate
  f->mutable_typed_config()->PackFrom(v);

  EXPECT_NO_THROW(factoryConfig->createCodecFactory(*cfg, context));
}

TEST_F(ChannelFilterFactoryConfigTest, Valid_TypedStruct) {
  // Make sure that using TypedStruct for enabled channel filter configs works the same way as
  // using regular Any. Checking that config validation is delayed is done in a separate test
  // further below.

  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();

  // The type will be known at the time the codec factory is created, otherwise the channel filter
  // factory wouldn't be able to load. However the type might not be known at the time the listener
  // configuration is received from the LDS.
  xds::type::v3::TypedStruct ts;
  ts.set_type_url("type.googleapis.com/envoy.config.core.v3.DataSource");
  // match the DataSource 'filename' field (in the 'specifier' oneof)
  auto* fields = ts.mutable_value()->mutable_fields();
  (*fields)["filename"].set_string_value("test");

  f->set_name("test_channel_filter");
  f->mutable_typed_config()->PackFrom(ts); // use the TypedStruct instead

  ASSERT_NO_THROW(factoryConfig->createCodecFactory(*cfg, context));
}

TEST_F(ChannelFilterFactoryConfigTest, Invalid_TypedStructWithWrongType) {
  // Similar to the above test using TypedStruct, but using a type that does not match and should
  // be rejected during creation of the codec factory.

  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();

  xds::type::v3::TypedStruct ts;
  ts.set_type_url("type.googleapis.com/google.protobuf.StringValue");
  auto* fields = ts.mutable_value()->mutable_fields();
  (*fields)["value"].set_string_value("test");
  f->set_name("test_channel_filter");
  f->mutable_typed_config()->PackFrom(ts);

  EXPECT_THROW_WITH_MESSAGE(factoryConfig->createCodecFactory(*cfg, context),
                            EnvoyException,
                            "type mismatch in configuration for channel filter factory 'test_channel_filter' "
                            "(expecting envoy.config.core.v3.DataSource, got google.protobuf.StringValue)");
}

TEST_F(ChannelFilterFactoryConfigTest, Invalid_MalformedTypedStruct) {
  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();

  f->set_name("test_channel_filter");
  f->mutable_typed_config()->set_type_url("type.googleapis.com/xds.type.v3.TypedStruct");
  f->mutable_typed_config()->set_value("malformed");

  EXPECT_THROW_WITH_MESSAGE(factoryConfig->createCodecFactory(*cfg, context),
                            EnvoyException,
                            "bug: malformed TypedStruct in channel filter factory config");
}

TEST_F(ChannelFilterFactoryConfigTest, Invalid_TypedStructWithMatchingTypeButMessageFailsValidation) {
  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();

  xds::type::v3::TypedStruct ts;
  ts.set_type_url("type.googleapis.com/envoy.config.core.v3.DataSource");
  auto* fields = ts.mutable_value()->mutable_fields();
  // the unknown field should be ignored, but the missing oneof should cause a validation error
  (*fields)["some_unknown_field"].set_string_value("asdf");
  f->set_name("test_channel_filter");
  f->mutable_typed_config()->PackFrom(ts);

  EXPECT_THROW_WITH_REGEX(factoryConfig->createCodecFactory(*cfg, context),
                          EnvoyException,
                          R"(Proto constraint validation failed \(field: "specifier", reason: is required\))");
}

TEST_F(ChannelFilterFactoryConfigTest, Invalid_TypedStructWithMatchingTypeButInvalidData_DecodeFailed) {
  auto cfg = newTestConfig();
  auto* f = cfg->add_enabled_channel_filter_factories();

  // this will trigger a (legitimate) json decode error which has a different error message
  xds::type::v3::TypedStruct ts;
  ts.set_type_url("type.googleapis.com/envoy.config.core.v3.DataSource");
  auto* fields = ts.mutable_value()->mutable_fields();
  (*fields)["filename"].set_number_value(1); // should be a string
  f->set_name("test_channel_filter");
  f->mutable_typed_config()->PackFrom(ts);

  EXPECT_THROW_WITH_REGEX(factoryConfig->createCodecFactory(*cfg, context),
                          EnvoyException,
                          "Unable to parse JSON as proto");
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

TEST(FactoryTest, DelayedChannelFilterFactoriesConfigValidation) {
  pomerium::extensions::ssh::CodecConfig cfg;

  auto good_config = R"(
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
)"s;

  // incorrect usage
  EXPECT_THROW_WITH_REGEX(
    TestUtility::loadFromYamlAndValidate(
      good_config + R"(
    enabled_channel_filter_factories:
      - name: dynamic
        typed_config:
          "@type": "type.googleapis.com/some.type.NotKnownUntilLater"
          value:
            foo: "bar"
    )",
      cfg);
    , Envoy::ProtoValidationException,
    "could not find @type 'type.googleapis.com/some.type.NotKnownUntilLater'");

  // correct usage
  EXPECT_NO_THROW(
    TestUtility::loadFromYamlAndValidate(
      good_config + R"(
    enabled_channel_filter_factories:
      - name: dynamic
        typed_config:
          "@type": "type.googleapis.com/xds.type.v3.TypedStruct"
          type_url: type.googleapis.com/some.type.NotKnownUntilLater
          value:
            foo: "bar"
    )",
      cfg));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec