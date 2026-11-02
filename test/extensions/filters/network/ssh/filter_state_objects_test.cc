#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "envoy/common/hashable.h"
#include "source/common/network/utility.h"
#include "gtest/gtest.h"
#include <type_traits>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

static_assert(!std::is_base_of_v<Envoy::Hashable, DownstreamSourceAddress>);
static_assert(!std::is_base_of_v<Envoy::Hashable, RequestedServerName>);
static_assert(!std::is_base_of_v<Envoy::Hashable, RequestedPath>);

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

TEST(FilterStateObjectsTest, RequestedPath) {
  RequestedPath obj("/foo");
  EXPECT_EQ("/foo", obj.value());
  EXPECT_EQ("/foo", obj.serializeAsString());
  EXPECT_EQ("pomerium.extensions.ssh.requested_path", RequestedPath::key());
}

TEST(FilterStateObjectsTest, RequestedPathFilterStateFactory) {
  RequestedPathFilterStateFactory factory;
  EXPECT_EQ("pomerium.extensions.ssh.requested_path", RequestedPathFilterStateFactory::key());
  auto obj = factory.createFromBytes("/foo");
  EXPECT_EQ("/foo", obj->serializeAsString());
}

TEST(FilterStateObjectsTest, DownstreamSourceAddress) {
  auto addrInstance = Network::Utility::parseInternetAddressAndPortNoThrow("127.0.0.1:12345");
  DownstreamSourceAddress obj(addrInstance);
  EXPECT_EQ("127.0.0.1:12345", obj.serializeAsString());
  EXPECT_EQ(addrInstance.get(), obj.getAddress().get());
  ASSERT_EQ(std::nullopt, DownstreamSourceAddress(nullptr).serializeAsString());
  EXPECT_EQ("pomerium.extensions.ssh.downstream_source_address", DownstreamSourceAddress::key());
}

TEST(FilterStateObjectsTest, DownstreamSourceAddressFilterStateFactory) {
  DownstreamSourceAddressFilterStateFactory factory;
  EXPECT_EQ("pomerium.extensions.ssh.downstream_source_address", DownstreamSourceAddressFilterStateFactory::key());
  auto obj = factory.createFromBytes("127.0.0.1:12345");
  ASSERT_NE(nullptr, obj);
  ASSERT_EQ(nullptr, dynamic_cast<Envoy::Hashable*>(obj.get()));
  EXPECT_EQ("127.0.0.1:12345", obj->serializeAsString());
  ASSERT_EQ(nullptr, factory.createFromBytes("not-an-ip"));
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec