#include "source/extensions/filters/network/ssh/stream_address.h"
#include "source/extensions/filters/network/ssh/reverse_tunnel.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace Envoy::Network {
namespace test {

class MockReverseTunnelClusterContext : public ReverseTunnelClusterContext {
public:
  MOCK_METHOD(const Upstream::ClusterInfoConstSharedPtr&, clusterInfo, ());
  MOCK_METHOD(std::shared_ptr<StreamTracker>, streamTracker, ());
  MOCK_METHOD(std::shared_ptr<const envoy::config::core::v3::Address>, chooseUpstreamAddress, ());
  MOCK_METHOD(ReverseTunnelStats&, reverseTunnelStats, ());
};

class FakeHostContext : public Network::HostContext {
public:
  FakeHostContext(const pomerium::extensions::ssh::EndpointMetadata& md)
      : metadata_(md) {}

  const pomerium::extensions::ssh::EndpointMetadata& hostMetadata() override { return metadata_; }
  Network::HostDrainManager& hostDrainManager() override { return host_drain_manager_; }
  Network::ReverseTunnelClusterContext& clusterContext() override { return cluster_context_; }

private:
  pomerium::extensions::ssh::EndpointMetadata metadata_;
  Network::HostDrainManager host_drain_manager_;
  testing::NiceMock<MockReverseTunnelClusterContext> cluster_context_;
};

TEST(SshStreamAddressTest, TestAddress) {
  pomerium::extensions::ssh::EndpointMetadata metadata;
  metadata.mutable_matched_permission()->set_requested_host("host");
  metadata.mutable_matched_permission()->set_requested_port(1234);
  metadata.mutable_server_port()->set_value(56789);
  metadata.mutable_server_port()->set_is_dynamic(true);
  FakeHostContext ctx(metadata);
  Network::Address::SshStreamAddress address(1, ctx);

  EXPECT_EQ(1, address.streamId());
  EXPECT_EQ(&ctx, &address.hostContext());
  EXPECT_EQ("ssh:1", address.asString());
  EXPECT_EQ("ssh:1", address.asStringView());
  EXPECT_EQ("ssh:1", address.logicalName());
  EXPECT_EQ("ssh_stream", address.addressType());

  EXPECT_EQ(nullptr, address.ip());
  EXPECT_EQ(nullptr, address.pipe());
  EXPECT_NE(nullptr, address.envoyInternalAddress());
  EXPECT_NE("", address.envoyInternalAddress()->addressId());  // should be non-empty (value is ignored)
  EXPECT_EQ("", address.envoyInternalAddress()->endpointId()); // should be empty
  EXPECT_EQ(nullptr, address.sockAddr());
  EXPECT_EQ(0, address.sockAddrLen());
  EXPECT_EQ(Network::Address::Type::EnvoyInternal, address.type());
  EXPECT_EQ(std::nullopt, address.networkNamespace());
  EXPECT_THROW_WITH_MESSAGE(address.socketInterface(),
                            Envoy::EnvoyException,
                            "unexpected call to socketInterface()");
}

TEST(SshStreamAddressTest, NoCompareEqual) {
  // Addresses should not compare equal
  FakeHostContext ctx({});
  Network::Address::SshStreamAddress address1(1, ctx);
  Network::Address::SshStreamAddress address2(1, ctx);

  EXPECT_NE(address1, address2);
}

} // namespace test
} // namespace Envoy::Network