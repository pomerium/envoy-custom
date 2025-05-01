#include "test/extensions/filters/network/ssh/test_data.h"
#include "test/extensions/filters/network/ssh/test_common.h"
#include "test/extensions/filters/network/ssh/test_config.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "gtest/gtest.h"
#include "gtest/gtest-spi.h"
#include <coroutine>

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

template <typename T>
T append(const T& input, auto... args) {
  auto out = input;
  for (const auto& a : {args...}) {
    out.push_back(a);
  }
  return out;
}

template <typename T>
void remove(std::vector<T>& v, const T& value) {
  v.erase(std::remove(v.begin(), v.end(), value), v.end());
}

#define EXPECT_SERVER_REPLY(type, ...)                                          \
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(MSG(type, __VA_ARGS__))) \
    .WillOnce(Return(static_cast<size_t>(0)))

#define EXPECT_SERVER_REPLY_VAR(var, type, ...)                                 \
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(MSG(type, __VA_ARGS__))) \
    .WillOnce(DoAll(SaveArg<0>(var), Return(static_cast<size_t>(0))))

static const wire::KexInitMsg normal_client_kex_init_msg = [] {
  wire::KexInitMsg msg;
  msg.cookie = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  msg.kex_algorithms = append(all_kex_algorithms, "ext-info-c", "kex-strict-c-v00@openssh.com");
  msg.server_host_key_algorithms = all_host_key_algorithms;
  msg.encryption_algorithms_client_to_server = all_ciphers;
  msg.encryption_algorithms_server_to_client = all_ciphers;
  msg.mac_algorithms_client_to_server = all_macs;
  msg.mac_algorithms_server_to_client = all_macs;
  msg.compression_algorithms_client_to_server = all_compression_algorithms;
  msg.compression_algorithms_server_to_client = all_compression_algorithms;
  msg.first_kex_packet_follows = false;
  msg.reserved = {};
  return msg;
}();

class TestMsgDispatcher : public MessageDispatcher<wire::Message> {
public:
  using MessageDispatcher<wire::Message>::dispatch;
};

enum SuspensionPoint {
  Begin,
  BeforeKexInitSent,
  AfterKexInitSent,
  BeforeEcdhInitSent,
  AfterEcdhInitSent,
  BeforeNewKeysSent,
  AfterNewKeysSent,
  BeforeExtInfoSent,
  AfterExtInfoSent,
};

struct KexSequence {
  struct promise_type;
  using handle_type = std::coroutine_handle<promise_type>;

  // NOLINTBEGIN(readability-identifier-naming)
  struct promise_type {
    SuspensionPoint suspension_point{Begin};
    std::exception_ptr exception;
    bool suppress_exceptions{false};

    KexSequence get_return_object() {
      return KexSequence{handle_type::from_promise(*this)};
    }

    std::suspend_always initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }

    void unhandled_exception() {
      exception = std::current_exception();
      if (!suppress_exceptions) {
        std::rethrow_exception(std::current_exception());
      }
    }

    void return_void() {}
    void await_resume() {}

    std::suspend_always yield_value(SuspensionPoint label) {
      suspension_point = label;
      return {};
    }
  };
  // NOLINTEND(readability-identifier-naming)

  KexSequence(const KexSequence&) = delete;
  KexSequence(KexSequence&& other) = delete;
  KexSequence& operator=(const KexSequence&) = delete;
  KexSequence& operator=(KexSequence&& other) noexcept {
    if (coro) {
      coro.destroy();
    }
    coro = nullptr;
    std::swap(coro, other.coro);
    return *this;
  }

  explicit KexSequence(handle_type h) noexcept
      : coro(h) {}

  ~KexSequence() {
    if (coro) {
      coro.destroy();
    }
  }

  bool resume() {
    if (!coro || coro.done()) {
      return false;
    }
    coro.resume();
    return !coro.done();
  }

  SuspensionPoint suspensionPoint() {
    return coro.promise().suspension_point;
  }

  void suppressExceptions() {
    coro.promise().suppress_exceptions = true;
  }

  std::exception_ptr getException() {
    return coro.promise().exception;
  }

  handle_type coro;

  wire::Message server_kex_init_;
  wire::Message server_ecdh_reply_;
  wire::KexInitMsg client_kex_init_;
  wire::KexEcdhInitMsg client_ecdh_init_;

  std::shared_ptr<KexResult> client_kex_result_;
  std::shared_ptr<KexResult> server_kex_result_;
};

template <typename... MsgTypes>
class DiscardHandler : public SshMessageHandler {
public:
  ~DiscardHandler() override {
    if (dispatcher_ != nullptr) {
      dispatcher_->unregisterHandler(this);
    }
  }

  absl::Status handleMessage(wire::Message&&) override {
    return absl::OkStatus();
  }

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override {
    (dispatcher.registerHandler(MsgTypes::type, this), ...);
    dispatcher_ = &dispatcher;
  };

private:
  MessageDispatcher<wire::Message>* dispatcher_;
};

class ServerKexTest : public testing::Test {
public:
  ServerKexTest()
      : sequence(startKexSequence(normal_client_kex_init_msg)),
        transport_callbacks_(std::make_unique<testing::StrictMock<MockTransportCallbacks>>()),
        kex_callbacks_(std::make_unique<testing::StrictMock<MockKexCallbacks>>()) {
    setupMockFilesystem(api_, file_system_);
    configureKeys(config_);
    client_host_keys_.push_back(*openssh::SSHKey::fromPrivateKeyFile(api_.fileSystem(), "client/test_host_ed25519_key"));
    client_host_keys_.push_back(*openssh::SSHKey::fromPrivateKeyFile(api_.fileSystem(), "client/test_host_rsa_key"));
  }

  void SetUp() override {
    kex_ = std::make_unique<Kex>(*transport_callbacks_, *kex_callbacks_, KexMode::Server);

    std::vector<openssh::SSHKeyPtr> hostKeys;
    for (const auto& key : config_->host_keys()) {
      auto r = openssh::SSHKey::fromPrivateKeyFile(api_.fileSystem(), key);
      if (!r.ok()) {
        PANIC(r.status());
      }
      auto blob = (*r)->toPublicKeyBlob();
      for (auto alg : (*r)->algorithmsForKeyType()) {
        host_key_blobs_[alg] = *blob;
      }
      hostKeys.push_back(std::move(*r));
    }
    ASSERT(hostKeys.size() == 2);
    kex_->setHostKeys(std::move(hostKeys));
    kex_->setVersionStrings("SSH-2.0-Server", "SSH-2.0-Client");
    kex_->registerMessageHandlers(dispatch_incoming_);

    ON_CALL(*transport_callbacks_, sendMessageDirect(VariantWith<wire::DisconnectMsg>(_)))
      .WillByDefault(Invoke([](wire::Message&& msg) {
        ADD_FAILURE() << fmt::format("received unexpected disconnect message: {}", msg.message.get<wire::DisconnectMsg>().description);
        return absl::StatusOr<size_t>{0};
      }));
  }

  void ContinueUntil(SuspensionPoint label) { // NOLINT
    while (sequence.resume()) {
      if (sequence.suspensionPoint() == label) {
        break;
      }
    }
  }

  void ContinueUntilEnd() { // NOLINT
    while (sequence.resume())
      ;
  }

  void ContinueAndExpectErrorBefore(SuspensionPoint label, absl::Status expected) { // NOLINT
    sequence.suppressExceptions();
    while (sequence.resume()) {
      if (sequence.suspensionPoint() == label) {
        FAIL() << "suspension point reached without failure";
        break;
      }
    }
    if (auto x = sequence.getException(); x) {
      try {
        std::rethrow_exception(x);
      } catch (const absl::Status& stat) {
        EXPECT_EQ(expected, stat);
        releaseMocks();
        return;
      }
      std::unreachable();
    } else {
      FAIL() << "sequence ended without failure";
    }
  }

  void releaseMocks() {
    // intentionally leak the mock objects so that they are never destroyed, and expectations
    // for functions that should be called are not checked.
    testing::Mock::AllowLeak(transport_callbacks_.release());
    testing::Mock::AllowLeak(kex_callbacks_.release());
  }

  // resets mocks, preserving default actions
  void resetMocks() {
    testing::Mock::VerifyAndClearExpectations(transport_callbacks_.get());
    testing::Mock::VerifyAndClearExpectations(kex_callbacks_.get());
  }

protected:
  std::vector<openssh::SSHKeyPtr> client_host_keys_;
  std::optional<bytes> session_id_;
  std::optional<bool> client_supports_ext_info_;

  KexSequence sequence;
  KexSequence startKexSequence(wire::KexInitMsg client_kex_init, bool initial_kex = true) {
    if (!initial_kex) {
      resetMocks();
    }

    // ensure all expected calls are ordered
    IN_SEQUENCE;

    // KexInit
    EXPECT_CALL(*kex_callbacks_, onKexStarted(initial_kex)).Times(1);
    EXPECT_CALL(*kex_callbacks_, onKexInitMsgSent()).Times(1);
    EXPECT_SERVER_REPLY_VAR(&sequence.server_kex_init_,
                            wire::KexInitMsg,
                            FIELD_EQ(kex_algorithms,
                                     initial_kex ? string_list{"curve25519-sha256", "curve25519-sha256@libssh.org", "ext-info-s", "kex-strict-s-v00@openssh.com"}
                                                 : string_list{"curve25519-sha256", "curve25519-sha256@libssh.org"}),
                            FIELD_EQ(server_host_key_algorithms, string_list{"ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"}),
                            FIELD_EQ(encryption_algorithms_client_to_server, string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}),
                            FIELD_EQ(encryption_algorithms_server_to_client, string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}),
                            FIELD_EQ(mac_algorithms_client_to_server, string_list{}),
                            FIELD_EQ(mac_algorithms_server_to_client, string_list{}),
                            FIELD_EQ(compression_algorithms_client_to_server, string_list{"none"}),
                            FIELD_EQ(compression_algorithms_server_to_client, string_list{"none"}),
                            FIELD_EQ(first_kex_packet_follows, false));

    sequence.client_kex_init_ = client_kex_init;
    // send client kex init
    co_yield BeforeKexInitSent;
    if (auto stat = dispatch_incoming_.dispatch(auto(sequence.client_kex_init_)); !stat.ok()) {
      throw stat; // don't try this at home
    }
    co_yield AfterKexInitSent;

    auto& pendingState = kex_->getPendingStateForTest();

    openssh::SSHKey* client_hostkey{};
    for (const auto& keypair : client_host_keys_) {
      for (const auto& keyAlg : algorithmsForKeyFormat(keypair->keyTypeName())) {
        if (pendingState.negotiated_algorithms.host_key == keyAlg) {
          client_hostkey = keypair.get();
          goto loop_done;
        }
      }
    }
  loop_done:

    HandshakeMagics magics{
      .client_version = "SSH-2.0-Client",
      .server_version = "SSH-2.0-Server",
      .client_kex_init = *encodeTo<bytes>(sequence.client_kex_init_),
      .server_kex_init = *encodeTo<bytes>(sequence.server_kex_init_),
    };

    Curve25519Sha256KexAlgorithm alg(&magics, &pendingState.negotiated_algorithms, client_hostkey);

    // ECDH
    EXPECT_SERVER_REPLY_VAR(&sequence.server_ecdh_reply_,
                            wire::KexEcdhReplyMsg,
                            FIELD_EQ(host_key, host_key_blobs_["ssh-ed25519"]));
    EXPECT_SERVER_REPLY(wire::NewKeysMsg, _);
    EXPECT_CALL(*transport_callbacks_, resetWriteSequenceNumber())
      .WillOnce(Return(3)); // KexInitMsg, KexEcdhReplyMsg, NewKeysMsg

    wire::Message clientInit = *alg.buildClientInit();
    clientInit.visit(
      [&](opt_ref<wire::KexEcdhInitMsg> msg) {
        sequence.client_ecdh_init_ = *msg;
      },
      [](auto&) {
        FAIL();
      });
    co_yield BeforeEcdhInitSent;
    if (auto stat = dispatch_incoming_.dispatch(auto(sequence.client_ecdh_init_)); !stat.ok()) {
      throw stat;
    }
    co_yield AfterEcdhInitSent;

    auto r = alg.handleClientRecv(sequence.server_ecdh_reply_);
    if (!r.ok()) {
      throw auto(r.status());
    }
    sequence.client_kex_result_ = **r;
    // some fields aren't filled by handleClientRecv, so set them to the expected values
    if (initial_kex) {
      sequence.client_kex_result_->session_id = sequence.client_kex_result_->exchange_hash;
      session_id_ = sequence.client_kex_result_->session_id;
    } else {
      sequence.client_kex_result_->session_id = session_id_.value();
    }
    sequence.client_kex_result_->server_supports_ext_info = true;
    if (initial_kex) {
      sequence.client_kex_result_->client_supports_ext_info = absl::c_contains(*sequence.client_kex_init_.kex_algorithms, "ext-info-c");
      client_supports_ext_info_ = sequence.client_kex_result_->client_supports_ext_info;
    } else {
      sequence.client_kex_result_->client_supports_ext_info = client_supports_ext_info_.value();
    }

    // NewKeys
    EXPECT_CALL(*transport_callbacks_, resetReadSequenceNumber())
      .WillOnce(Return(3)); // KexInitMsg, KexEcdhInitMsg, NewKeysMsg

    DiscardHandler<wire::IgnoreMsg> ignoreHandler;
    EXPECT_CALL(*kex_callbacks_, onKexCompleted(_, initial_kex))
      .WillOnce(DoAll(SaveArg<0>(&sequence.server_kex_result_), [&] {
        ignoreHandler.registerMessageHandlers(dispatch_incoming_);
      }));

    co_yield BeforeNewKeysSent;
    if (auto stat = dispatch_incoming_.dispatch(wire::Message{wire::NewKeysMsg{}}); !stat.ok()) {
      throw stat;
    }
    co_yield AfterNewKeysSent;

    if (initial_kex) {
      // Client ExtInfo (server ext info won't be received, it is sent by the server transport)
      wire::ExtInfoMsg clientExtInfo;
      wire::PingExtension ping;
      ping.version = "0";
      clientExtInfo.extensions->emplace_back(std::move(ping));

      co_yield BeforeExtInfoSent;
      if (sequence.client_kex_result_->client_supports_ext_info) {
        EXPECT_CALL(*transport_callbacks_, updatePeerExtInfo(std::optional{clientExtInfo}))
          .WillOnce(Return());
        if (auto stat = dispatch_incoming_.dispatch(wire::Message{std::move(clientExtInfo)}); !stat.ok()) {
          throw stat;
        }
      }
      co_yield AfterExtInfoSent;
    }

    // Done
    EXPECT_EQ(*sequence.client_kex_result_, *sequence.server_kex_result_);

    co_return;
  }

  NiceMock<Api::MockApi> api_;
  NiceMock<Filesystem::MockInstance> file_system_;
  std::unordered_map<std::string_view, bytes> host_key_blobs_; // alg->blob

  std::shared_ptr<CodecConfig> config_{newConfig()};

  std::unique_ptr<testing::StrictMock<MockTransportCallbacks>> transport_callbacks_;
  std::unique_ptr<testing::StrictMock<MockKexCallbacks>> kex_callbacks_;
  std::unique_ptr<Kex> kex_;
  TestMsgDispatcher dispatch_incoming_;
};

TEST_F(ServerKexTest, BasicKeyExchange) {
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, NoExtInfo) {
  ContinueUntil(BeforeKexInitSent);
  remove(*sequence.client_kex_init_.kex_algorithms, "ext-info-c"s);
  ContinueUntil(BeforeExtInfoSent);
  EXPECT_FALSE(sequence.client_kex_result_->client_supports_ext_info);
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, StrictMode) {
  ContinueUntil(BeforeKexInitSent);
  remove(*sequence.client_kex_init_.kex_algorithms, "kex-strict-c-v00@openssh.com"s);

  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError("strict key exchange mode is required"));
}

// TODO: there is probably a better way to set up these tests
class StrictModeEnforcementBeforeKexInitTest : public ServerKexTest, public testing::WithParamInterface<wire::Message> {};

TEST_P(StrictModeEnforcementBeforeKexInitTest, BeforeKexInit) {
  ContinueUntil(BeforeKexInitSent);
  auto r = dispatch_incoming_.dispatch(auto(GetParam()));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), fmt::format("unexpected message received: {}", GetParam().msg_type()));
  releaseMocks();
}
INSTANTIATE_TEST_SUITE_P(BeforeKexInit, StrictModeEnforcementBeforeKexInitTest,
                         testing::ValuesIn({
                           wire::Message{wire::IgnoreMsg{}},
                           wire::Message{wire::DebugMsg{}},
                           wire::Message{wire::UnimplementedMsg{}},
                           wire::Message{wire::KexEcdhReplyMsg{}},
                           wire::Message{wire::ExtInfoMsg{}},
                           wire::Message{wire::NewKeysMsg{}},
                         }));

class StrictModeEnforcementBeforeEcdhInitTest : public ServerKexTest, public testing::WithParamInterface<wire::Message> {};

TEST_P(StrictModeEnforcementBeforeEcdhInitTest, BeforeEcdhInit) {
  ContinueUntil(BeforeEcdhInitSent);
  auto r = dispatch_incoming_.dispatch(auto(GetParam()));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), fmt::format("unexpected message received: {}", GetParam().msg_type()));
  releaseMocks();
}
INSTANTIATE_TEST_SUITE_P(BeforeEcdhInit, StrictModeEnforcementBeforeEcdhInitTest,
                         testing::ValuesIn({
                           wire::Message{wire::IgnoreMsg{}},
                           wire::Message{wire::DebugMsg{}},
                           wire::Message{wire::UnimplementedMsg{}},
                           wire::Message{wire::KexInitMsg{}},
                           wire::Message{wire::KexEcdhReplyMsg{}},
                           wire::Message{wire::ExtInfoMsg{}},
                           wire::Message{wire::NewKeysMsg{}},
                         }));

class StrictModeEnforcementBeforeNewKeysTest : public ServerKexTest, public testing::WithParamInterface<wire::Message> {};
TEST_P(StrictModeEnforcementBeforeNewKeysTest, BeforeNewKeys) {
  ContinueUntil(BeforeNewKeysSent);
  auto r = dispatch_incoming_.dispatch(auto(GetParam()));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), fmt::format("key exchange error: expected NewKeys, received {}", GetParam().msg_type()));
  releaseMocks();
}
INSTANTIATE_TEST_SUITE_P(BeforeNewKeys, StrictModeEnforcementBeforeNewKeysTest,
                         testing::ValuesIn({
                           wire::Message{wire::IgnoreMsg{}},
                           wire::Message{wire::DebugMsg{}},
                           wire::Message{wire::UnimplementedMsg{}},
                           wire::Message{wire::KexInitMsg{}},
                           wire::Message{wire::KexEcdhReplyMsg{}},
                           wire::Message{wire::ExtInfoMsg{}},
                         }));

TEST_F(ServerKexTest, StrictModeEnforcement_AfterNewKeys) {
  ContinueUntil(BeforeKexInitSent);
  remove(*sequence.client_kex_init_.kex_algorithms, "ext-info-c"s);
  ContinueUntil(AfterNewKeysSent);
  EXPECT_OK(dispatch_incoming_.dispatch(wire::Message{wire::IgnoreMsg{}}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, StrictModeEnforcement_AfterExtInfo) {
  ContinueUntil(AfterExtInfoSent);
  EXPECT_OK(dispatch_incoming_.dispatch(wire::Message{wire::IgnoreMsg{}}));
  ContinueUntilEnd();
}

class AlgorithmNegotiationTest : public ServerKexTest, public testing::WithParamInterface<wire::Message> {};

TEST_F(AlgorithmNegotiationTest, NoCommonKexAlgorithms) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.kex_algorithms = {"diffie-hellman-group-exchange-sha256",
                                              "diffie-hellman-group16-sha512",
                                              "diffie-hellman-group18-sha512",
                                              "diffie-hellman-group14-sha256",
                                              "ext-info-c",
                                              "kex-strict-c-v00@openssh.com"};

  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   fmt::format("no common algorithm for key exchange; client offered: {}; server offered: {}",
                                                               sequence.client_kex_init_.kex_algorithms,
                                                               append(preferredKexAlgos, "ext-info-s", "kex-strict-s-v00@openssh.com"))));
}

TEST_F(AlgorithmNegotiationTest, InvalidKeyExchangeMethod) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.kex_algorithms = {
    "ext-info-s",
    "kex-strict-c-v00@openssh.com",
  };

  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   "negotiated an invalid key exchange method: ext-info-s"));
}

TEST_F(AlgorithmNegotiationTest, NoCommonHostKey) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.server_host_key_algorithms = {"never-before-seen"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   fmt::format("no common algorithm for host key; client offered: {}; server offered: {}",
                                                               sequence.client_kex_init_.server_host_key_algorithms,
                                                               string_list{"ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerCipher) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_client_to_server = {"never-before-seen"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   fmt::format("no common algorithm for client to server cipher; client offered: {}; server offered: {}",
                                                               sequence.client_kex_init_.encryption_algorithms_client_to_server,
                                                               string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientCipher) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_server_to_client = {"never-before-seen"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   fmt::format("no common algorithm for server to client cipher; client offered: {}; server offered: {}",
                                                               sequence.client_kex_init_.encryption_algorithms_server_to_client,
                                                               string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerMac) {
  ContinueUntil(BeforeKexInitSent);
  // as long as an AEAD cipher is selected, mac algorithms are not negotiated
  sequence.client_kex_init_.mac_algorithms_client_to_server = {"never-before-seen"};
  ContinueUntilEnd();
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientMac) {
  ContinueUntil(BeforeKexInitSent);
  // as long as an AEAD cipher is selected, mac algorithms are not negotiated
  sequence.client_kex_init_.mac_algorithms_server_to_client = {"never-before-seen"};
  ContinueUntilEnd();
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerCompression) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.compression_algorithms_client_to_server = {"gzip", "zstd"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   fmt::format("no common algorithm for client to server compression; client offered: {}; server offered: {}",
                                                               sequence.client_kex_init_.compression_algorithms_client_to_server,
                                                               string_list{"none"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientCompression) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.compression_algorithms_server_to_client = {"gzip", "zstd"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::InvalidArgumentError(
                                                   fmt::format("no common algorithm for server to client compression; client offered: {}; server offered: {}",
                                                               sequence.client_kex_init_.compression_algorithms_server_to_client,
                                                               string_list{"none"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerLanguage) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.languages_client_to_server = {"foo"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::UnimplementedError("unsupported client to server language"));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientLanguage) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.languages_server_to_client = {"foo"};
  ContinueAndExpectErrorBefore(AfterKexInitSent, absl::UnimplementedError("unsupported server to client language"));
}

TEST_F(ServerKexTest, IncorrectClientGuess_KexAlg) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.first_kex_packet_follows = true;
  ContinueUntil(BeforeEcdhInitSent);
  wire::KexEcdhInitMsg ecdhInit;
  ecdhInit.client_pub_key = wire::test::random_value<bytes>();
  EXPECT_OK(dispatch_incoming_.dispatch(wire::Message{ecdhInit}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, IncorrectClientGuess_HostKeyAlg) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.first_kex_packet_follows = true;
  sequence.client_kex_init_.server_host_key_algorithms = {"bad-first-guess", "ssh-ed25519", "rsa-sha2-512", "ssh-rsa"};
  ContinueUntil(BeforeEcdhInitSent);
  wire::KexEcdhInitMsg ecdhInit;
  ecdhInit.client_pub_key = wire::test::random_value<bytes>();
  EXPECT_OK(dispatch_incoming_.dispatch(wire::Message{ecdhInit}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, IncorrectClientGuess_WrongMessageType) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.first_kex_packet_follows = true;
  ContinueUntil(BeforeEcdhInitSent);
  auto r = dispatch_incoming_.dispatch(wire::Message{wire::IgnoreMsg{}});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r, absl::InvalidArgumentError("unexpected message received: Ignore (2)"));
  releaseMocks();
}

TEST_F(ServerKexTest, ClientInitiatedRekey) {
  ContinueUntilEnd();
  auto rekeyInit = normal_client_kex_init_msg;
  rekeyInit.kex_algorithms = all_kex_algorithms;
  sequence = startKexSequence(rekeyInit, false);
  ContinueUntilEnd();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec