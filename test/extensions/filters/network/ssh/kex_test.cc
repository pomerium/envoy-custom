#include "source/extensions/filters/network/ssh/transport_base.h"
#include "test/extensions/filters/network/ssh/test_data.h"
#include "test/mocks/server/factory_context.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/test_common.h"
#include "test/extensions/filters/network/ssh/test_config.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"

namespace wire {
template <typename T>
constexpr bool holds_alternative(const Message& msg) {
  return msg.message.holds_alternative<T>();
}
template <typename T>
constexpr bool holds_alternative(Message&& msg) {
  return std::move(msg).message.holds_alternative<T>();
}
template <typename T>
constexpr decltype(auto) get(const Message& msg) {
  return msg.message.template get<T>();
}
template <typename T>
constexpr decltype(auto) get(Message&& msg) {
  return std::move(msg).message.template get<T>();
}

} // namespace wire
namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

namespace test {

static const string_list all_kex_algorithms = {
  "mlkem768x25519-sha256",
  "sntrup761x25519-sha512",
  "sntrup761x25519-sha512@openssh.com",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
  "ecdh-sha2-nistp256",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp521",
  "diffie-hellman-group-exchange-sha256",
  "diffie-hellman-group16-sha512",
  "diffie-hellman-group18-sha512",
  "diffie-hellman-group14-sha256",
};

static const string_list all_host_key_algorithms = {
  "ssh-ed25519-cert-v01@openssh.com",
  "ecdsa-sha2-nistp256-cert-v01@openssh.com",
  "ecdsa-sha2-nistp384-cert-v01@openssh.com",
  "ecdsa-sha2-nistp521-cert-v01@openssh.com",
  "sk-ssh-ed25519-cert-v01@openssh.com",
  "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
  "rsa-sha2-512-cert-v01@openssh.com",
  "rsa-sha2-256-cert-v01@openssh.com",
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
  "rsa-sha2-512",
  "rsa-sha2-256",
};

static const string_list all_ciphers = {
  "chacha20-poly1305@openssh.com",
  "aes128-gcm@openssh.com",
  "aes256-gcm@openssh.com",
  "aes128-ctr",
  "aes192-ctr",
  "aes256-ctr",
};

static const string_list all_macs = {
  "umac-64-etm@openssh.com",
  "umac-128-etm@openssh.com",
  "hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512-etm@openssh.com",
  "hmac-sha1-etm@openssh.com",
  "umac-64@openssh.com",
  "umac-128@openssh.com",
  "hmac-sha2-256",
  "hmac-sha2-512",
  "hmac-sha1",
};

static const string_list all_compression_algorithms = {
  "none",
  "zlib@openssh.com",
};

class TestMsgDispatcher : public MessageDispatcher<wire::Message> {
public:
  using MessageDispatcher<wire::Message>::dispatch;
};

class ServerKexTest : public testing::Test {
public:
  ServerKexTest() {
    setupMockFilesystem(api_, file_system_);
    configureKeys(config_);
    kex_ = std::make_unique<Kex>(transport_callbacks_, kex_callbacks_, KexMode::Server);

    std::vector<openssh::SSHKeyPtr> hostKeys;
    for (const auto& key : config_->host_keys()) {
      auto r = openssh::SSHKey::fromPrivateKeyFile(api_.fileSystem(), key);
      if (!r.ok()) {
        PANIC(r.status());
      }
      hostKeys.push_back(std::move(*r));
    }
    ASSERT(hostKeys.size() == 2);
    kex_->setHostKeys(std::move(hostKeys));
    kex_->setVersionStrings("SSH-2.0-Server", "SSH-2.0-Client");
    kex_->registerMessageHandlers(dispatch_incoming_);
  }

protected:
  NiceMock<Api::MockApi> api_;
  NiceMock<Filesystem::MockInstance> file_system_;

  std::shared_ptr<CodecConfig> config_{newConfig()};

  testing::StrictMock<MockTransportCallbacks> transport_callbacks_;
  testing::StrictMock<MockKexCallbacks> kex_callbacks_;
  std::unique_ptr<Kex> kex_;
  TestMsgDispatcher dispatch_incoming_;
};

template <typename T>
T append(const T& input, auto... args) {
  auto out = input;
  for (const auto& a : {args...}) {
    out.push_back(a);
  }
  return out;
}

TEST_F(ServerKexTest, BasicKeyExchange) {
  using wire::KexInitMsg;
  KexInitMsg clientKexInit;
  clientKexInit.cookie = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  clientKexInit.kex_algorithms = append(all_kex_algorithms, "ext-info-c", "kex-strict-c-v00@openssh.com");
  clientKexInit.server_host_key_algorithms = all_host_key_algorithms;
  clientKexInit.encryption_algorithms_client_to_server = all_ciphers;
  clientKexInit.encryption_algorithms_server_to_client = all_ciphers;
  clientKexInit.mac_algorithms_client_to_server = all_macs;
  clientKexInit.mac_algorithms_server_to_client = all_macs;
  clientKexInit.compression_algorithms_client_to_server = all_compression_algorithms;
  clientKexInit.compression_algorithms_server_to_client = all_compression_algorithms;
  clientKexInit.first_kex_packet_follows = false;
  clientKexInit.reserved = {};

  EXPECT_CALL(kex_callbacks_, onKexStarted(true)).Times(1);
  EXPECT_CALL(kex_callbacks_, onKexInitMsgSent).Times(1);

  EXPECT_CALL(
    transport_callbacks_,
    sendMessageDirect(
      MSG(KexInitMsg,
          FIELD_EQ(kex_algorithms, string_list{"curve25519-sha256", "curve25519-sha256@libssh.org", "ext-info-s", "kex-strict-s-v00@openssh.com"}),
          FIELD_EQ(server_host_key_algorithms, string_list{"ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"}),
          FIELD_EQ(encryption_algorithms_client_to_server, string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}),
          FIELD_EQ(encryption_algorithms_server_to_client, string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}),
          FIELD_EQ(mac_algorithms_client_to_server, string_list{}),
          FIELD_EQ(mac_algorithms_server_to_client, string_list{}),
          FIELD_EQ(compression_algorithms_client_to_server, string_list{"none"}),
          FIELD_EQ(compression_algorithms_server_to_client, string_list{"none"}),
          FIELD_EQ(first_kex_packet_follows, false))));
  dispatch_incoming_.dispatch(std::move(clientKexInit))
    .IgnoreError();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec