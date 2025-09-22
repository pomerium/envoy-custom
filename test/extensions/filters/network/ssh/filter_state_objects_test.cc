#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

TEST(FilterStateObjectsTest, RequestedServerName) {
  RequestedServerName obj("test name");
  EXPECT_EQ("test name", obj.value());
  EXPECT_EQ("test name", obj.serializeAsString());
  EXPECT_EQ("pomerium.extensions.ssh.requested_server_name", RequestedServerName::key());
}

TEST(FilterStateObjectsTest, RequestedServerNameFilterStateFactory) {
  RequestedServerNameFilterStateFactory factory;
  EXPECT_EQ("pomerium.extensions.ssh.requested_server_name", RequestedServerNameFilterStateFactory::key());
  auto obj = factory.createFromBytes("test name");
  EXPECT_EQ("test name", obj->serializeAsString());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec