#pragma once

#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/integration/http_integration.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {

class FakeStreamShimImpl : public FakeStreamShim {
public:
  explicit FakeStreamShimImpl(std::unique_ptr<FakeStream> real_fake)
      : real_fake_(std::move(real_fake)) {}

  void startGrpcStream() override {
    return real_fake_->startGrpcStream();
  }
  testing::AssertionResult waitForGrpcMessage(Envoy::Event::Dispatcher& client_dispatcher,
                                              Protobuf::Message& message,
                                              std::chrono::milliseconds timeout) override {
    return real_fake_->waitForGrpcMessage(client_dispatcher, message, timeout);
  }

  void sendGrpcMessage(const Protobuf::Message& message) override {
    return real_fake_->sendGrpcMessage(message);
  }

  std::unique_ptr<FakeStream> real_fake_;
};

class FakeHttpConnectionShimImpl : public FakeHttpConnectionShim {
public:
  explicit FakeHttpConnectionShimImpl(std::unique_ptr<FakeHttpConnection> real_fake)
      : real_fake_(std::move(real_fake)) {}

  [[nodiscard]]
  testing::AssertionResult waitForNewStream(Envoy::Event::Dispatcher& client_dispatcher,
                                            std::unique_ptr<FakeStreamShim>& stream,
                                            std::chrono::milliseconds timeout) override {
    std::unique_ptr<FakeStream> real;
    auto ret = real_fake_->waitForNewStream(client_dispatcher, real, timeout);
    stream = std::make_unique<FakeStreamShimImpl>(std::move(real));
    return ret;
  }

  [[nodiscard]]
  testing::AssertionResult close(Network::ConnectionCloseType close_type,
                                 std::chrono::milliseconds timeout) override {
    return real_fake_->close(close_type, timeout);
  }

  std::unique_ptr<FakeHttpConnection> real_fake_;
};

class FakeUpstreamShimImpl : public FakeUpstreamShim {
public:
  FakeUpstreamShimImpl() = default;

  explicit FakeUpstreamShimImpl(FakeUpstream* fake_upstream)
      : fake_upstream_(fake_upstream) {}

  [[nodiscard]]
  testing::AssertionResult waitForHttpConnection(Envoy::Event::Dispatcher& client_dispatcher,
                                                 std::unique_ptr<FakeHttpConnectionShim>& connection,
                                                 std::chrono::milliseconds timeout) override {
    std::unique_ptr<FakeHttpConnection> real;
    auto ret = fake_upstream_->waitForHttpConnection(client_dispatcher, real, timeout);
    connection = std::make_unique<FakeHttpConnectionShimImpl>(std::move(real));
    return ret;
  }

private:
  FakeUpstream* fake_upstream_{};
};

class SshIntegrationTest : public SecretsProviderImpl,
                           public HttpIntegrationTest {
  // Implementation note:
  // SecretsProviderImpl has to be a separate base class, initialized before HttpIntegrationTest,
  // and must create the ssh keys. The HttpIntegrationTest constructor needs the string config,
  // which we need to format using the generated keys. If we stored the keys in SshIntegrationTest
  // and initialized them e.g. inside defaultConfig(), they would be deleted when the members of
  // SshIntegrationTest are default-initialized, which happens after the HttpIntegrationTest
  // constructor completes.
protected:
  SshIntegrationTest(std::vector<std::string> ssh_routes, Network::Address::IpVersion version);
  ~SshIntegrationTest();

  void initialize() override;

  std::string localhost() const {
    return (version_ == Network::Address::IpVersion::v4)
             ? "127.0.0.1"
             : "::1";
  }

  std::string defaultConfig(const std::vector<std::string>& routes);

  std::shared_ptr<SshConnectionDriver> makeSshConnectionDriver();
  IntegrationTcpClientPtr makeTcpConnectionWithServerName(uint32_t port, const std::string& server_name);

  FakeUpstreamShimImpl mgmt_upstream_;
  FakeUpstreamShimImpl http_upstream_1_;
  FakeUpstreamShimImpl http_upstream_2_;
  FakeUpstreamShimImpl tcp_upstream_;
  std::vector<FakeUpstreamShimImpl> ssh_upstreams_;
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec