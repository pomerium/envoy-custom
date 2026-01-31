#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SecretsProviderImpl : public SecretsProvider {
public:
  std::vector<openssh::SSHKeySharedPtr> hostKeys() const override {
    return {host_key_};
  };

  openssh::SSHKeySharedPtr userCaKey() const override {
    return user_ca_key_;
  };

  openssh::SSHKeySharedPtr host_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
  openssh::SSHKeySharedPtr user_ca_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
};

using ChannelMsgHandlerFunc = absl::AnyInvocable<absl::Status(wire::ChannelMessage&&, ChannelCallbacks&)>;

struct SshFakeUpstreamHandlerOpts {
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenMsg&)> on_channel_open_request;
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenConfirmationMsg&)> on_channel_accepted;
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenFailureMsg&)> on_channel_rejected;
};

class FakeSshUpstreamCallbacks {
public:
  virtual ~FakeSshUpstreamCallbacks() = default;
  virtual void onNewConnection(Envoy::Network::Connection& connection) PURE;
};

class FakeSshUpstreamShim {
public:
  virtual ~FakeSshUpstreamShim() = default;

  virtual void handleNextSshConnection(FakeSshUpstreamCallbacks& handler) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec