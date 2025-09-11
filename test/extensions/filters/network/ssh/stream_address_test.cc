#include "source/extensions/filters/network/ssh/stream_address.h"
#include "gtest/gtest.h"
#include "test/test_common/test_common.h"
#include "envoy/network/socket_interface.h"
#include "test/mocks/event/mocks.h"

namespace Envoy::Network::Address {
namespace test {

class FakeSocketInterface : public SocketInterface {
public:
  IoHandlePtr socket(Socket::Type, Address::Type, Address::IpVersion, bool, const SocketCreationOptions&) const override { return nullptr; }
  IoHandlePtr socket(Socket::Type, const Address::InstanceConstSharedPtr, const SocketCreationOptions&) const override { return nullptr; }
  bool ipFamilySupported(int) override { return true; }
};

class FakeSocketInterfaceFactory : public SocketInterfaceFactory {
public:
  std::unique_ptr<SocketInterface> createSocketInterface(Event::Dispatcher&) {
    return std::make_unique<FakeSocketInterface>();
  }
};

class InternalStreamAddressImplTest : public testing::Test {
public:
  void SetUp() {
    fake_socket_interface_factory_ = std::make_shared<FakeSocketInterfaceFactory>();
  }
  std::shared_ptr<FakeSocketInterfaceFactory> fake_socket_interface_factory_;
};

TEST_F(InternalStreamAddressImplTest, FactoryAddress) {
  pomerium::extensions::ssh::EndpointMetadata metadata;
  metadata.mutable_matched_permission()->set_requested_host("host");
  metadata.mutable_matched_permission()->set_requested_port(1234);
  metadata.mutable_server_port()->set_value(56789);
  metadata.mutable_server_port()->set_is_dynamic(true);
  auto md = std::make_shared<envoy::config::core::v3::Metadata>();
  (*md->mutable_typed_filter_metadata())["com.pomerium.ssh.endpoint"].PackFrom(metadata);
  InternalStreamAddressImpl address(1, md, fake_socket_interface_factory_);

  EXPECT_EQ(1, address.streamId());
  EXPECT_EQ(md, address.endpointMetadata());
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
  EXPECT_EQ(Type::EnvoyInternal, address.type());
  EXPECT_EQ(std::nullopt, address.networkNamespace());

  EXPECT_EQ(fake_socket_interface_factory_.get(), &address.socketInterfaceFactory());
}

TEST_F(InternalStreamAddressImplTest, CreateFromFactoryAddress) {
  pomerium::extensions::ssh::EndpointMetadata metadata;
  metadata.mutable_matched_permission()->set_requested_host("host");
  metadata.mutable_matched_permission()->set_requested_port(1234);
  metadata.mutable_server_port()->set_value(56789);
  metadata.mutable_server_port()->set_is_dynamic(true);
  auto md = std::make_shared<envoy::config::core::v3::Metadata>();
  (*md->mutable_typed_filter_metadata())["com.pomerium.ssh.endpoint"].PackFrom(metadata);
  auto factory_address = std::make_shared<InternalStreamAddressImpl>(1, md, fake_socket_interface_factory_);
  NiceMock<Event::MockDispatcher> dispatcher;
  auto address = InternalStreamAddressImpl::createFromFactoryAddress(factory_address, dispatcher);

  EXPECT_EQ(factory_address->streamId(), address->streamId());
  EXPECT_EQ(factory_address->endpointMetadata(), address->endpointMetadata());
  EXPECT_EQ(factory_address->asString(), address->asString());
  EXPECT_EQ(factory_address->asStringView(), address->asStringView());
  EXPECT_EQ(factory_address->logicalName(), address->logicalName());
  EXPECT_EQ(factory_address->addressType(), address->addressType());
  EXPECT_EQ(factory_address->addressType(), address->addressType());

  EXPECT_EQ(factory_address->ip(), address->ip());
  EXPECT_EQ(factory_address->pipe(), address->pipe());
  EXPECT_NE(nullptr, address->envoyInternalAddress());
  EXPECT_NE(factory_address->envoyInternalAddress(), address->envoyInternalAddress());                             // these addresses should not be the same
  EXPECT_EQ(factory_address->envoyInternalAddress()->addressId(), address->envoyInternalAddress()->addressId());   // should be non-empty (value is ignored)
  EXPECT_EQ(factory_address->envoyInternalAddress()->endpointId(), address->envoyInternalAddress()->endpointId()); // should be empty
  EXPECT_EQ(factory_address->sockAddr(), address->sockAddr());
  EXPECT_EQ(factory_address->sockAddrLen(), address->sockAddrLen());
  EXPECT_EQ(factory_address->type(), address->type());
  EXPECT_EQ(factory_address->networkNamespace(), address->networkNamespace());

  EXPECT_NE(nullptr, &address->socketInterface());
}

TEST_F(InternalStreamAddressImplTest, NoCompareEqual) {
  // Addresses should not compare equal
  auto metadata = std::make_shared<envoy::config::core::v3::Metadata>();
  InternalStreamAddressImpl address1(1, metadata, fake_socket_interface_factory_);
  InternalStreamAddressImpl address2(1, metadata, fake_socket_interface_factory_);

  EXPECT_NE(address1, address2);
}

} // namespace test
} // namespace Envoy::Network::Address