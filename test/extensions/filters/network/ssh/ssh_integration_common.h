#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "gtest/gtest-assertion-result.h"

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

// These shims allow us to skip including fake_upstream.h in this file, since it is massive
// and adds like 90 seconds to the compile time of any TU that includes it. Modifications to
// just the connection driver should be much quicker to build.

class FakeStreamShim {
public:
  virtual ~FakeStreamShim() = default;
  virtual void startGrpcStream() PURE;
  virtual testing::AssertionResult
  waitForGrpcMessage(Envoy::Event::Dispatcher& client_dispatcher, Protobuf::Message& message,
                     std::chrono::milliseconds timeout) PURE;

  virtual void sendGrpcMessage(const Protobuf::Message& message) PURE;
};

class FakeHttpConnectionShim {
public:
  virtual ~FakeHttpConnectionShim() = default;
  [[nodiscard]]
  virtual testing::AssertionResult waitForNewStream(
    Envoy::Event::Dispatcher& client_dispatcher, std::unique_ptr<FakeStreamShim>& stream,
    std::chrono::milliseconds timeout) PURE;
  [[nodiscard]]
  virtual testing::AssertionResult close(Network::ConnectionCloseType close_type, std::chrono::milliseconds timeout) PURE;
  [[nodiscard]]
  virtual testing::AssertionResult waitForDisconnect(std::chrono::milliseconds timeout) PURE;
};

using ChannelMsgHandlerFunc = absl::AnyInvocable<absl::Status(wire::ChannelMessage&&, ChannelCallbacks&)>;
using OnChannelDestroyedFunc = absl::AnyInvocable<void()>;

class FakeUpstreamHandlerApi {
public:
  virtual ~FakeUpstreamHandlerApi() = default;
  virtual void closeConnection(Network::ConnectionCloseType) PURE;
};

class FakeSshUpstreamHandlerApi : public FakeUpstreamHandlerApi {
public:
  virtual ~FakeSshUpstreamHandlerApi() = default;
  virtual void requestChannelOpen() PURE;
};

struct SshFakeUpstreamHandlerOpts {
  std::function<bool(uint32_t)> should_accept_channel = [](uint32_t) { return true; };
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenMsg&)> on_channel_open_request;
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenConfirmationMsg&)> on_channel_accepted;
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenFailureMsg&)> on_channel_rejected;
  absl::AnyInvocable<OnChannelDestroyedFunc(uint32_t, Envoy::Event::Dispatcher&, ChannelCallbacks&)> on_channel_created;
  absl::AnyInvocable<void(const wire::DisconnectMsg&)> on_disconnect;
  absl::AnyInvocable<void(FakeSshUpstreamHandlerApi&)> set_upstream_api;
};

struct HttpFakeUpstreamHandlerOpts {
  absl::AnyInvocable<std::shared_ptr<Envoy::Network::ReadFilter>()> add_read_filter;
  absl::AnyInvocable<void(FakeUpstreamHandlerApi&)> set_upstream_api;
};

class FakeUpstreamHandlerCallbacks {
public:
  virtual ~FakeUpstreamHandlerCallbacks() = default;
  virtual void onNewConnection(Envoy::Network::Connection& connection) PURE;
};

class FakeUpstreamShim {
public:
  virtual ~FakeUpstreamShim() = default;

  [[nodiscard]]
  virtual testing::AssertionResult waitForHttpConnection(Envoy::Event::Dispatcher& client_dispatcher,
                                                         std::unique_ptr<FakeHttpConnectionShim>& connection,
                                                         std::chrono::milliseconds timeout) PURE;

  [[nodiscard]]
  virtual testing::AssertionResult listenForSshConnection(std::shared_ptr<SshFakeUpstreamHandlerOpts> opts,
                                                          Server::Configuration::ServerFactoryContext& ctx) PURE;

  [[nodiscard]]
  virtual testing::AssertionResult listenForHttpConnection(std::shared_ptr<HttpFakeUpstreamHandlerOpts> opts,
                                                           Server::Configuration::ServerFactoryContext& ctx) PURE;

  virtual void cleanup(absl::Duration timeout) PURE;
};

class SshIntegrationTestApi {
public:
  virtual std::unique_ptr<FakeUpstreamShim> newFakeUpstream(Http::CodecType type, const std::string& name) PURE;
  virtual testing::AssertionResult listenForSshConnection(SshFakeUpstreamHandlerOpts&& opts, size_t upstream_index = 0) PURE;
  virtual testing::AssertionResult listenForHttpConnection(HttpFakeUpstreamHandlerOpts&& opts, FakeUpstreamShim& fake_upstream) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec