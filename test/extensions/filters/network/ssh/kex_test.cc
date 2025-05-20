#include "source/extensions/filters/network/ssh/kex_alg_curve25519.h"
#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"
#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "test/test_common/test_common.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_util.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "gtest/gtest.h"
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

// The <typename = void> parameter below is used to ensure the static_assert expressions reachable
// from the else block are discarded, which only occurs in a dependent context. We are using macro
// substitution to insert the typename here, so the condition is otherwise not dependent.
// See https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2593r0.html for more details.
#define EXPECT_SERVER_REPLY_VAR(var, type, ...)                                            \
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(MSG(type, __VA_ARGS__)))            \
    .WillOnce(Invoke([&]<typename = void>(wire::Message&& msg) -> absl::StatusOr<size_t> { \
      if constexpr (wire::detail::is_overloaded_message<std::decay_t<type>>) {             \
        msg.visit([&](opt_ref<type> m) { var = m.value(); },                               \
                  [](auto&) { FAIL(); });                                                  \
      } else {                                                                             \
        msg.visit([&](type m) { var = m; },                                                \
                  [](auto&) { FAIL(); });                                                  \
      }                                                                                    \
      return 0;                                                                            \
    }))

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

static const wire::KexInitMsg normal_server_kex_init_msg = [] {
  wire::KexInitMsg msg;
  msg.cookie = {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  msg.kex_algorithms = append(all_kex_algorithms, "ext-info-s", "kex-strict-s-v00@openssh.com");
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

struct KexSequence {
  struct promise_type;
  using handle_type = std::coroutine_handle<promise_type>;

  // NOLINTBEGIN(readability-identifier-naming)
  struct promise_type {
    int suspension_point{0};
    std::optional<absl::Status> result;

    KexSequence get_return_object() {
      return KexSequence{handle_type::from_promise(*this)};
    }

    std::suspend_always initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }

    void unhandled_exception() {}

    void return_value(absl::Status status) {
      result = status;
    }
    void await_resume() {}

    std::suspend_always yield_value(int label) {
      suspension_point = label;
      return {};
    }
  };
  // NOLINTEND(readability-identifier-naming)

  KexSequence(const KexSequence&) = delete;
  KexSequence(KexSequence&& other) noexcept {
    if (coro) {
      coro.destroy();
      coro = nullptr;
    }
    std::swap(coro, other.coro);
  }
  KexSequence& operator=(const KexSequence&) = delete;
  KexSequence& operator=(KexSequence&& other) noexcept {
    if (coro) {
      coro.destroy();
      coro = nullptr;
    }
    std::swap(coro, other.coro);
    return *this;
  }

  ~KexSequence() {
    if (coro) {
      coro.destroy();
      coro = nullptr;
    }
  }

  explicit KexSequence(handle_type h) noexcept
      : coro(h) {}

  bool resume() {
    ASSERT(coro != nullptr);
    EXPECT_FALSE(coro.done()) << "sequence exited unexpectedly with status: " << coro.promise().result->ToString();
    if (coro.done()) {
      return false;
    }
    coro.resume();
    return !coro.done();
  }

  int suspensionPoint() {
    return coro.promise().suspension_point;
  }

  absl::Status result() {
    ASSERT(coro != nullptr);
    ASSERT(coro.done());
    ASSERT(coro.promise().result.has_value());
    return coro.promise().result.value();
  }

  handle_type coro;

  wire::KexInitMsg server_kex_init_;
  wire::KexInitMsg client_kex_init_;
  wire::KexEcdhReplyMsg server_ecdh_reply_;
  wire::KexEcdhInitMsg client_ecdh_init_;

  std::shared_ptr<KexResult> client_kex_result_;
  std::shared_ptr<KexResult> server_kex_result_;

  bool expecting_error_{false};
};

template <typename... MsgTypes>
class DiscardHandler : public SshMessageHandler {
public:
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

class BaseKexTest : public testing::Test {
public:
  BaseKexTest(KexSequence&& sequence)
      : sequence(std::move(sequence)) {

    client_host_keys_.push_back(*openssh::SSHKey::generate(KEY_ED25519, 256));
    client_host_keys_.push_back(*openssh::SSHKey::generate(KEY_ECDSA, 256));
    client_host_keys_.push_back(*openssh::SSHKey::generate(KEY_ECDSA, 384));
    client_host_keys_.push_back(*openssh::SSHKey::generate(KEY_ECDSA, 521));
    client_host_keys_.push_back(*openssh::SSHKey::generate(KEY_RSA, 2048));

    algorithm_factories_.registerType<Curve25519Sha256KexAlgorithmFactory>();
    cipher_factories_.registerType<Chacha20Poly1305CipherFactory>();
    cipher_factories_.registerType<AESGCM128CipherFactory>();
    cipher_factories_.registerType<AESGCM256CipherFactory>();
    cipher_factories_.registerType<AES128CTRCipherFactory>();
    cipher_factories_.registerType<AES192CTRCipherFactory>();
    cipher_factories_.registerType<AES256CTRCipherFactory>();

    peer_reply_ = std::make_unique<TestMsgDispatcher>();
    transport_callbacks_ = std::make_unique<testing::StrictMock<MockTransportCallbacks>>();
    kex_callbacks_ = std::make_unique<testing::StrictMock<MockKexCallbacks>>();
  }

  auto newServerHostKeys() {
    std::vector<openssh::SSHKeyPtr> hostKeys;
    hostKeys.push_back(*openssh::SSHKey::generate(KEY_ED25519, 256));
    hostKeys.push_back(*openssh::SSHKey::generate(KEY_ECDSA, 256));
    hostKeys.push_back(*openssh::SSHKey::generate(KEY_ECDSA, 384));
    hostKeys.push_back(*openssh::SSHKey::generate(KEY_ECDSA, 521));
    hostKeys.push_back(*openssh::SSHKey::generate(KEY_RSA, 2048));

    std::unordered_map<std::string, bytes> hostKeyBlobs;
    for (const auto& key : hostKeys) {
      const auto blob = key->toPublicKeyBlob();
      ASSERT(blob.ok());
      for (auto alg : key->signatureAlgorithmsForKeyType()) {
        hostKeyBlobs[alg] = *blob;
      }
    }
    return std::make_pair(std::move(hostKeys), std::move(hostKeyBlobs));
  }

  void ContinueUntil(int label) { // NOLINT
    while (sequence.resume()) {
      if (sequence.suspensionPoint() == label) {
        return;
      }
    }
    FAIL() << "coroutine never reached expected suspension point";
  }

  void ContinueUntilEnd() { // NOLINT
    while (sequence.resume())
      ;
    EXPECT_OK(sequence.result());
    sequence.coro.destroy();
    sequence.coro = nullptr;
  }

  void ContinueAndExpectError(absl::Status expected) { // NOLINT
    sequence.expecting_error_ = true;
    auto res = sequence.resume();
    EXPECT_FALSE(res) << "sequence did not exit with an error";
    EXPECT_EQ(expected, sequence.result());
  }

  // Like ContinueAndExpectError, but all the usual function calls are still expected. This is for
  // checking errors that don't short-circuit parts of the key exchange routine.
  void ContinueAndExpectSoftError(absl::Status expected) { // NOLINT
    auto res = sequence.resume();
    EXPECT_FALSE(res) << "sequence did not exit with an error";
    EXPECT_EQ(expected, sequence.result());
  }

  // resets mocks, preserving default actions
  void verifyAndResetMocks() {
    testing::Mock::VerifyAndClearExpectations(transport_callbacks_.get());
    testing::Mock::VerifyAndClearExpectations(kex_callbacks_.get());
  }

protected:
  KexSequence sequence;

  std::vector<openssh::SSHKeyPtr> server_host_keys_;
  std::vector<openssh::SSHKeyPtr> client_host_keys_;
  std::optional<bytes> session_id_;

  std::unique_ptr<Kex> kex_;

  std::unique_ptr<TestMsgDispatcher> peer_reply_;
  std::unique_ptr<testing::StrictMock<MockTransportCallbacks>> transport_callbacks_;
  std::unique_ptr<testing::StrictMock<MockKexCallbacks>> kex_callbacks_;

  KexAlgorithmFactoryRegistry algorithm_factories_;
  DirectionalPacketCipherFactoryRegistry cipher_factories_;
};

class ServerKexTest : public BaseKexTest {
public:
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

    DoInitiateRekey = 99,
  };

  ServerKexTest()
      : BaseKexTest(startKexSequence(normal_client_kex_init_msg)) {}
  void SetUp() override {
    kex_ = std::make_unique<Kex>(*transport_callbacks_, *kex_callbacks_, algorithm_factories_, cipher_factories_, KexMode::Server);
    auto&& [hostKeys, hostKeyBlobs] = newServerHostKeys();
    kex_->setHostKeys(std::move(hostKeys));
    host_key_blobs_ = std::move(hostKeyBlobs);
    kex_->setVersionStrings("SSH-2.0-Server", "SSH-2.0-Client");
    kex_->registerMessageHandlers(*peer_reply_);
  }

protected:
  std::optional<bool> client_supports_ext_info_;
  std::unordered_map<std::string, bytes> host_key_blobs_; // alg->blob

  KexSequence startKexSequence(wire::KexInitMsg client_kex_init, bool initial_kex = true, bool server_initiated_rekey = false) {
    if (!initial_kex) {
      verifyAndResetMocks();
    }

    // ensure all expected calls are ordered
    IN_SEQUENCE;

    // KexInit
    sequence.client_kex_init_ = client_kex_init;
    // send client kex init
    co_yield BeforeKexInitSent;
    if (!sequence.expecting_error_) {
      auto expectOnKexStarted = [&] { EXPECT_CALL(*kex_callbacks_, onKexStarted(initial_kex)).Times(1); };
      auto expectOnKexInitMsgSent = [&] { EXPECT_CALL(*kex_callbacks_, onKexInitMsgSent()); };
      auto expectServerKexInit = [&] {
        EXPECT_SERVER_REPLY_VAR(sequence.server_kex_init_,
                                wire::KexInitMsg,
                                FIELD_EQ(kex_algorithms,
                                         initial_kex ? append(algorithm_factories_.namesByPriority(), "ext-info-s", "kex-strict-s-v00@openssh.com")
                                                     : algorithm_factories_.namesByPriority()),
                                FIELD_EQ(server_host_key_algorithms, string_list{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512"}),
                                FIELD_EQ(encryption_algorithms_client_to_server, cipher_factories_.namesByPriority()),
                                FIELD_EQ(encryption_algorithms_server_to_client, cipher_factories_.namesByPriority()),
                                FIELD_EQ(mac_algorithms_client_to_server, SupportedMACs),
                                FIELD_EQ(mac_algorithms_server_to_client, SupportedMACs),
                                FIELD_EQ(compression_algorithms_client_to_server, string_list{"none"}),
                                FIELD_EQ(compression_algorithms_server_to_client, string_list{"none"}),
                                FIELD_EQ(first_kex_packet_follows, false));
      };
      // the order of operations is different depending on who initiates the key (re-)exchange
      if (server_initiated_rekey) {
        expectOnKexInitMsgSent();
        expectServerKexInit();
        expectOnKexStarted();
      } else {
        expectOnKexStarted();
        expectOnKexInitMsgSent();
        expectServerKexInit();
      }
    }
    if (server_initiated_rekey) {
      co_yield DoInitiateRekey;
    }
    if (auto stat = peer_reply_->dispatch(auto(sequence.client_kex_init_)); !stat.ok()) {
      co_return stat;
    }
    co_yield AfterKexInitSent;

    auto& pendingState = kex_->getPendingStateForTest();

    openssh::SSHKey* client_hostkey{};
    for (const auto& keypair : client_host_keys_) {
      for (const auto& keyAlg : keypair->signatureAlgorithmsForKeyType()) {
        if (pendingState.negotiated_algorithms.host_key == keyAlg) {
          client_hostkey = keypair.get();
          goto loop_done;
        }
      }
    }
  loop_done:
    EXPECT_TRUE(client_hostkey != nullptr);

    HandshakeMagics magics{
      .client_version = "SSH-2.0-Client",
      .server_version = "SSH-2.0-Server",
      .client_kex_init = *encodeTo<bytes>(sequence.client_kex_init_),
      .server_kex_init = *encodeTo<bytes>(sequence.server_kex_init_),
    };

    auto alg = algorithm_factories_
                 .factoryForName(pendingState.negotiated_algorithms.kex)
                 ->create(&magics, &pendingState.negotiated_algorithms, client_hostkey);

    // ECDH
    wire::Message clientInit = alg->buildClientInit();
    clientInit.visit(
      [&](opt_ref<wire::KexEcdhInitMsg> msg) {
        sequence.client_ecdh_init_ = *msg;
      },
      [](auto&) {
        FAIL();
      });
    co_yield BeforeEcdhInitSent;
    if (!sequence.expecting_error_) {
      EXPECT_SERVER_REPLY_VAR(sequence.server_ecdh_reply_,
                              wire::KexEcdhReplyMsg,
                              FIELD_EQ(host_key, host_key_blobs_["ssh-ed25519"]));
      EXPECT_SERVER_REPLY(wire::NewKeysMsg, _);
      EXPECT_CALL(*transport_callbacks_, resetWriteSequenceNumber())
        .WillOnce(Return(3)); // KexInitMsg, KexEcdhReplyMsg, NewKeysMsg
    }
    if (auto stat = peer_reply_->dispatch(auto(sequence.client_ecdh_init_)); !stat.ok()) {
      co_return stat;
    }
    co_yield AfterEcdhInitSent;

    wire::Message tmp{sequence.server_ecdh_reply_};
    auto r = alg->handleClientRecv(tmp);
    if (!r.ok()) {
      co_return r.status();
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
    co_yield BeforeNewKeysSent;
    DiscardHandler<wire::IgnoreMsg> ignoreHandler;
    if (!sequence.expecting_error_) {
      EXPECT_CALL(*transport_callbacks_, resetReadSequenceNumber())
        .WillOnce(Return(3)); // KexInitMsg, KexEcdhInitMsg, NewKeysMsg
      EXPECT_CALL(*kex_callbacks_, onKexCompleted(_, initial_kex))
        .WillOnce(DoAll(SaveArg<0>(&sequence.server_kex_result_), [&] {
          ignoreHandler.registerMessageHandlers(*peer_reply_);
        }));
    }
    if (auto stat = peer_reply_->dispatch(wire::Message{wire::NewKeysMsg{}}); !stat.ok()) {
      co_return stat;
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
        if (!sequence.expecting_error_) {
          EXPECT_CALL(*transport_callbacks_, updatePeerExtInfo(std::optional{clientExtInfo}))
            .WillOnce(Return());
        }
        if (auto stat = peer_reply_->dispatch(wire::Message{std::move(clientExtInfo)}); !stat.ok()) {
          co_return stat;
        }
      }
      co_yield AfterExtInfoSent;
    }

    // Done
    EXPECT_EQ(*sequence.client_kex_result_, *sequence.server_kex_result_);

    peer_reply_->unregisterHandler(&ignoreHandler);
    co_return absl::OkStatus();
  }
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
  ContinueAndExpectSoftError(absl::InvalidArgumentError("strict key exchange mode is required"));
}

// TODO: there is probably a better way to set up these tests
class StrictModeEnforcementBeforeKexInitTest : public ServerKexTest, public testing::WithParamInterface<wire::Message> {};

TEST_P(StrictModeEnforcementBeforeKexInitTest, BeforeKexInit) {
  ContinueUntil(BeforeKexInitSent);
  auto r = peer_reply_->dispatch(auto(GetParam()));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), fmt::format("unexpected message received: {}", GetParam().msg_type()));
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
  auto r = peer_reply_->dispatch(auto(GetParam()));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), fmt::format("unexpected message received: {}", GetParam().msg_type()));
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
  auto r = peer_reply_->dispatch(auto(GetParam()));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), fmt::format("key exchange error: expected NewKeys, received {}", GetParam().msg_type()));
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
  EXPECT_OK(peer_reply_->dispatch(wire::Message{wire::IgnoreMsg{}}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, StrictModeEnforcement_AfterExtInfo) {
  ContinueUntil(AfterExtInfoSent);
  EXPECT_OK(peer_reply_->dispatch(wire::Message{wire::IgnoreMsg{}}));
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

  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for key exchange; client offered: {}; server offered: {}",
                sequence.client_kex_init_.kex_algorithms,
                append(algorithm_factories_.namesByPriority(), "ext-info-s", "kex-strict-s-v00@openssh.com"))));
}

TEST_F(AlgorithmNegotiationTest, InvalidKeyExchangeMethod) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.kex_algorithms = {
    "ext-info-s",
    "kex-strict-c-v00@openssh.com",
  };

  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    "negotiated an invalid key exchange method: ext-info-s"));
}

TEST_F(AlgorithmNegotiationTest, NoCommonHostKey) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.server_host_key_algorithms = {"never-before-seen"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for host key; client offered: {}; server offered: {}",
                sequence.client_kex_init_.server_host_key_algorithms,
                string_list{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerCipher) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_client_to_server = {"never-before-seen"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for client to server cipher; client offered: {}; server offered: {}",
                sequence.client_kex_init_.encryption_algorithms_client_to_server,
                string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientCipher) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_server_to_client = {"never-before-seen"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for server to client cipher; client offered: {}; server offered: {}",
                sequence.client_kex_init_.encryption_algorithms_server_to_client,
                string_list{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerMac) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_client_to_server = {CipherAES128CTR};
  sequence.client_kex_init_.mac_algorithms_client_to_server = {"hmac-md5"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for client to server MAC; client offered: {}; server offered: {}",
                sequence.client_kex_init_.mac_algorithms_client_to_server,
                SupportedMACs)));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientMac) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_server_to_client = {CipherAES128CTR};
  sequence.client_kex_init_.mac_algorithms_server_to_client = {"hmac-md5"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for server to client MAC; client offered: {}; server offered: {}",
                sequence.client_kex_init_.mac_algorithms_server_to_client,
                SupportedMACs)));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerMac_AEAD) {
  ContinueUntil(BeforeKexInitSent);
  // as long as an AEAD cipher is selected, mac algorithms are not negotiated
  sequence.client_kex_init_.mac_algorithms_client_to_server = {"never-before-seen"};
  ContinueUntilEnd();
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientMac_AEAD) {
  ContinueUntil(BeforeKexInitSent);
  // as long as an AEAD cipher is selected, mac algorithms are not negotiated
  sequence.client_kex_init_.mac_algorithms_server_to_client = {"never-before-seen"};
  ContinueUntilEnd();
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerCompression) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.compression_algorithms_client_to_server = {"gzip", "zstd"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for client to server compression; client offered: {}; server offered: {}",
                sequence.client_kex_init_.compression_algorithms_client_to_server,
                string_list{"none"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientCompression) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.compression_algorithms_server_to_client = {"gzip", "zstd"};
  ContinueAndExpectSoftError(absl::InvalidArgumentError(
    fmt::format("no common algorithm for server to client compression; client offered: {}; server offered: {}",
                sequence.client_kex_init_.compression_algorithms_server_to_client,
                string_list{"none"})));
}

TEST_F(AlgorithmNegotiationTest, NoCommonClientToServerLanguage) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.languages_client_to_server = {"foo"};
  ContinueAndExpectSoftError(absl::UnimplementedError("unsupported client to server language"));
}

TEST_F(AlgorithmNegotiationTest, NoCommonServerToClientLanguage) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.languages_server_to_client = {"foo"};
  ContinueAndExpectSoftError(absl::UnimplementedError("unsupported server to client language"));
}

TEST_F(ServerKexTest, IncorrectClientGuess_KexAlg) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.first_kex_packet_follows = true;
  ContinueUntil(BeforeEcdhInitSent);
  wire::KexEcdhInitMsg ecdhInit;
  ecdhInit.client_pub_key = wire::test::random_value<bytes>();
  EXPECT_OK(peer_reply_->dispatch(wire::Message{ecdhInit}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, IncorrectClientGuess_HostKeyAlg) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.first_kex_packet_follows = true;
  sequence.client_kex_init_.server_host_key_algorithms = {"bad-first-guess", "ssh-ed25519", "rsa-sha2-512"};
  ContinueUntil(BeforeEcdhInitSent);
  wire::KexEcdhInitMsg ecdhInit;
  ecdhInit.client_pub_key = wire::test::random_value<bytes>();
  EXPECT_OK(peer_reply_->dispatch(wire::Message{ecdhInit}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, IncorrectClientGuess_WrongMessageType) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.first_kex_packet_follows = true;
  ContinueUntil(BeforeEcdhInitSent);
  auto r = peer_reply_->dispatch(wire::Message{wire::IgnoreMsg{}});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r, absl::InvalidArgumentError("unexpected message received: Ignore (2)"));
}

TEST_F(ServerKexTest, ClientInitiatedRekey) {
  ContinueUntilEnd();
  for (auto i = 0; i < 10; i++) {
    auto rekeyInit = normal_client_kex_init_msg;
    rekeyInit.kex_algorithms = all_kex_algorithms;
    sequence = startKexSequence(rekeyInit, false);
    ContinueUntilEnd();
  }
}

TEST_F(ServerKexTest, DifferentDirectionAlgorithms) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.encryption_algorithms_client_to_server = {CipherChacha20Poly1305};
  sequence.client_kex_init_.encryption_algorithms_server_to_client = {CipherAES256CTR};
  sequence.client_kex_init_.mac_algorithms_client_to_server->clear();
  sequence.client_kex_init_.mac_algorithms_server_to_client = {"hmac-sha2-512-etm@openssh.com"};
  ContinueUntilEnd();
  EXPECT_EQ(CipherChacha20Poly1305, sequence.server_kex_result_->algorithms.client_to_server.cipher);
  EXPECT_EQ(CipherChacha20Poly1305, sequence.client_kex_result_->algorithms.client_to_server.cipher);

  EXPECT_EQ(CipherAES256CTR, sequence.server_kex_result_->algorithms.server_to_client.cipher);
  EXPECT_EQ(CipherAES256CTR, sequence.client_kex_result_->algorithms.server_to_client.cipher);

  EXPECT_EQ("", sequence.server_kex_result_->algorithms.client_to_server.mac);
  EXPECT_EQ("", sequence.client_kex_result_->algorithms.client_to_server.mac);

  EXPECT_EQ("hmac-sha2-512-etm@openssh.com", sequence.server_kex_result_->algorithms.server_to_client.mac);
  EXPECT_EQ("hmac-sha2-512-etm@openssh.com", sequence.client_kex_result_->algorithms.server_to_client.mac);
}

TEST_F(ServerKexTest, ClientInitiatedRekey_NewAlgorithms) {
  ContinueUntilEnd();
  auto rekeyInit = normal_client_kex_init_msg;
  rekeyInit.encryption_algorithms_client_to_server = {"aes256-gcm@openssh.com"};
  rekeyInit.encryption_algorithms_server_to_client = {"aes256-gcm@openssh.com"};
  sequence = startKexSequence(rekeyInit, false);
  ContinueUntilEnd();
  EXPECT_EQ("aes256-gcm@openssh.com", sequence.server_kex_result_->algorithms.client_to_server.cipher);
  EXPECT_EQ("aes256-gcm@openssh.com", sequence.server_kex_result_->algorithms.server_to_client.cipher);
}

TEST_F(ServerKexTest, ServerInitiatedRekey) {
  ContinueUntilEnd();
  for (auto i = 0; i < 10; i++) {
    auto rekeyInit = normal_client_kex_init_msg;
    rekeyInit.kex_algorithms = all_kex_algorithms;
    sequence = startKexSequence(rekeyInit, false, true);
    ContinueUntil(DoInitiateRekey);
    ASSERT_OK(kex_->initiateKex());
    ContinueUntilEnd();
  }
}

TEST_F(ServerKexTest, ServerInitiatedRekey_InvalidUsage1) {
  ContinueUntilEnd();
  sequence = startKexSequence(normal_client_kex_init_msg, false, true);
  ContinueUntil(DoInitiateRekey);
  ASSERT_OK(kex_->initiateKex());
  ContinueUntil(BeforeEcdhInitSent); // need to wait for peer's KexInit to be received
  EXPECT_ENVOY_BUG(kex_->initiateKex().IgnoreError(), "bug: initiateKex called during key exchange");
}

TEST_F(ServerKexTest, ServerInitiatedRekey_InvalidUsage2) {
  EXPECT_ENVOY_BUG(kex_->initiateKex().IgnoreError(), "bug: server cannot start initial key exchange");
}

TEST_F(ServerKexTest, EcdhFailure_KeySize) {
  ContinueUntil(BeforeEcdhInitSent);
  auto b = wire::test::random_value<bytes>();
  b.resize(std::min(b.size(), 30uz));
  sequence.client_ecdh_init_.client_pub_key = b;
  ContinueAndExpectError(absl::InvalidArgumentError(
    fmt::format("key exchange failed: invalid peer public key size (expected 32, got {})", b.size())));
}

// clang-format off

// from https://github.com/google/boringssl/blob/main/crypto/curve25519/x25519_test.cc
static const fixed_bytes<32> kSmallOrderPoint = {
  0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
  0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
  0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8,
};

// clang-format on

TEST_F(ServerKexTest, EcdhFailure_X25519) {
  ContinueUntil(BeforeEcdhInitSent);
  sequence.client_ecdh_init_.client_pub_key = to_bytes(kSmallOrderPoint);
  ContinueAndExpectError(absl::InvalidArgumentError("key exchange failed: x25519 error"));
}

TEST_F(ServerKexTest, SendReplyFail) {
  ContinueUntil(BeforeEcdhInitSent);
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(VariantWith<wire::detail::overload_set_for_t<wire::KexEcdhReplyMsg>>(_)))
    .WillOnce(Return(absl::InternalError("test error")));
  ContinueAndExpectError(absl::InternalError("test error"));
}

TEST_F(ServerKexTest, SendNewKeysFail) {
  ContinueUntil(BeforeEcdhInitSent);
  IN_SEQUENCE;
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(VariantWith<wire::detail::overload_set_for_t<wire::KexEcdhReplyMsg>>(_)))
    .WillOnce(Return(static_cast<size_t>(0)));
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(VariantWith<wire::NewKeysMsg>(_)))
    .WillOnce(Return(absl::InternalError("test error")));
  ContinueAndExpectError(absl::InternalError("test error"));
}

TEST_F(ServerKexTest, UnexpectedKexInit) {
  ContinueUntil(AfterKexInitSent);
  auto r = peer_reply_->dispatch(wire::Message{wire::KexInitMsg{}});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.message(), "unexpected message received: KexInit (20)");
}

TEST_F(ServerKexTest, SendKexInitFail) {
  ContinueUntil(BeforeKexInitSent);
  EXPECT_CALL(*kex_callbacks_, onKexStarted(true));
  // important: onKexInitMsgSent() is called before sending the message
  EXPECT_CALL(*kex_callbacks_, onKexInitMsgSent());
  EXPECT_CALL(*transport_callbacks_, sendMessageDirect(VariantWith<wire::KexInitMsg>(_)))
    .WillOnce(Return(absl::InternalError("test error")));
  ContinueAndExpectError(absl::InternalError("test error"));
}

class TestMultiStepKexAlgorithm : public Curve25519Sha256KexAlgorithm {
public:
  using Curve25519Sha256KexAlgorithm::Curve25519Sha256KexAlgorithm;

  bool first{true};

  const MessageTypeList& clientInitMessageTypes() const override {
    static MessageTypeList list{wire::KexEcdhInitMsg::type, wire::DebugMsg::type};
    return list;
  }

  absl::StatusOr<std::optional<KexResultSharedPtr>> handleServerRecv(wire::Message& msg) override {
    if (first) {
      first = false;
      EXPECT_EQ(msg.msg_type(), wire::DebugMsg::type);
      return std::optional<KexResultSharedPtr>{};
    }
    EXPECT_EQ(msg.msg_type(), wire::KexEcdhInitMsg::type);
    return Curve25519Sha256KexAlgorithm::handleServerRecv(msg);
  }
};

class TestMultiStepKexAlgorithmFactory : public Curve25519Sha256KexAlgorithmFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{"test-multi-step", 99}};
  }
  std::unique_ptr<KexAlgorithm> create(
    const HandshakeMagics* magics,
    const Algorithms* algs,
    const openssh::SSHKey* signer) const override {
    return std::make_unique<TestMultiStepKexAlgorithm>(magics, algs, signer);
  }
};

TEST_F(ServerKexTest, MultiStepAlgorithm) {
  algorithm_factories_.registerType<TestMultiStepKexAlgorithmFactory>();
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_.kex_algorithms = {"test-multi-step", "kex-strict-c-v00@openssh.com"};
  ContinueUntil(BeforeEcdhInitSent);
  EXPECT_OK(peer_reply_->dispatch(wire::Message{wire::DebugMsg{}}));
  ContinueUntilEnd();
}

TEST_F(ServerKexTest, PickHostKey) {
  EXPECT_EQ(*kex_->pickHostKey("ssh-ed25519"), **openssh::SSHKey::fromPublicKeyBlob(host_key_blobs_["ssh-ed25519"]));
  EXPECT_EQ(*kex_->pickHostKey("rsa-sha2-512"), **openssh::SSHKey::fromPublicKeyBlob(host_key_blobs_["rsa-sha2-512"]));
  EXPECT_EQ(*kex_->pickHostKey("rsa-sha2-256"), **openssh::SSHKey::fromPublicKeyBlob(host_key_blobs_["rsa-sha2-256"]));
  EXPECT_EQ(kex_->pickHostKey("ssh-rsa"), nullptr); // sha1 (deprecated)
  EXPECT_EQ(kex_->pickHostKey("nonexistent"), nullptr);
  EXPECT_EQ(kex_->pickHostKey("rsa-sha2-256-cert-v01@openssh.com"), nullptr);
  EXPECT_EQ(kex_->pickHostKey("ssh-ed25519-cert-v01@openssh.com"), nullptr);
}

TEST_F(ServerKexTest, GetHostKey) {
  EXPECT_EQ(*kex_->getHostKey(KEY_ED25519), **openssh::SSHKey::fromPublicKeyBlob(host_key_blobs_["ssh-ed25519"]));
  EXPECT_EQ(*kex_->getHostKey(KEY_RSA), **openssh::SSHKey::fromPublicKeyBlob(host_key_blobs_["rsa-sha2-512"]));
  EXPECT_EQ(kex_->getHostKey(static_cast<sshkey_types>(99)), nullptr);
}

class MakePacketCipherTest : public ServerKexTest, public testing::WithParamInterface<std::function<wire::KexInitMsg()>> {};

TEST_P(MakePacketCipherTest, MakePacketCipher) {
  ContinueUntil(BeforeKexInitSent);
  sequence.client_kex_init_ = GetParam()();
  ContinueUntilEnd();

  auto serverCipher = kex_->makePacketCipher(clientKeys, serverKeys, KexMode::Server, sequence.server_kex_result_.get());
  auto clientCipher = kex_->makePacketCipher(serverKeys, clientKeys, KexMode::Client, sequence.client_kex_result_.get());

  seqnum_t seqnum = 0;
  for (auto [send, recv] : {std::pair{serverCipher.get(), clientCipher.get()},
                            std::pair{clientCipher.get(), serverCipher.get()}}) {
    wire::Message msg;
    wire::DebugMsg debugMsg;
    debugMsg.message = "hello world";
    msg.message = std::move(debugMsg);

    Buffer::OwnedImpl plaintext;
    Buffer::OwnedImpl ciphertext;
    ASSERT_OK(wire::encodePacket(plaintext,
                                 msg,
                                 send->blockSize(openssh::CipherMode::Write),
                                 send->aadSize(openssh::CipherMode::Write))
                .status());
    ASSERT_OK(send->encryptPacket(seqnum, ciphertext, plaintext));

    Buffer::OwnedImpl decrypted;
    ASSERT_OK(recv->decryptPacket(seqnum, decrypted, ciphertext).status());
    seqnum++;
    wire::Message msg2;
    ASSERT_OK(wire::decodePacket(decrypted, msg2).status());
    EXPECT_EQ(msg, msg2);
  }
}

INSTANTIATE_TEST_SUITE_P(
  MakePacketCipherTestSuite, MakePacketCipherTest,
  testing::ValuesIn(std::vector<std::function<wire::KexInitMsg()>>{
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherChacha20Poly1305};
      kexInit.encryption_algorithms_server_to_client = {CipherChacha20Poly1305};
      kexInit.mac_algorithms_client_to_server->clear();
      kexInit.mac_algorithms_server_to_client->clear();
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherChacha20Poly1305};
      kexInit.encryption_algorithms_server_to_client = {CipherChacha20Poly1305};
      kexInit.mac_algorithms_client_to_server = SupportedMACs;
      kexInit.mac_algorithms_server_to_client = SupportedMACs;
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherAES256CTR, CipherAES192CTR};
      kexInit.encryption_algorithms_server_to_client = {CipherAES256CTR, CipherAES192CTR};
      kexInit.mac_algorithms_client_to_server = SupportedMACs;
      kexInit.mac_algorithms_server_to_client = SupportedMACs;
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherChacha20Poly1305};
      kexInit.encryption_algorithms_server_to_client = {CipherAES256CTR};
      kexInit.mac_algorithms_client_to_server->clear();
      kexInit.mac_algorithms_server_to_client = {"hmac-sha2-512-etm@openssh.com"};
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherAES256CTR};
      kexInit.encryption_algorithms_server_to_client = {CipherChacha20Poly1305};
      kexInit.mac_algorithms_client_to_server = {"hmac-sha2-512-etm@openssh.com"};
      kexInit.mac_algorithms_server_to_client->clear();
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherAES256CTR, CipherAES192CTR};
      kexInit.encryption_algorithms_server_to_client = {CipherAES192CTR, CipherAES256CTR};
      kexInit.mac_algorithms_client_to_server = SupportedMACs;
      kexInit.mac_algorithms_server_to_client = SupportedMACs | std::views::reverse | std::ranges::to<std::vector>();
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherChacha20Poly1305};
      kexInit.encryption_algorithms_server_to_client = {CipherAES256GCM};
      kexInit.mac_algorithms_client_to_server = SupportedMACs;
      kexInit.mac_algorithms_server_to_client = SupportedMACs;
      return kexInit;
    },
    [] {
      auto kexInit = normal_client_kex_init_msg;
      kexInit.encryption_algorithms_client_to_server = {CipherAES256GCM, CipherAES256CTR, CipherAES192CTR};
      kexInit.encryption_algorithms_server_to_client = {CipherAES192CTR, CipherAES256CTR};
      kexInit.mac_algorithms_client_to_server->clear();
      kexInit.mac_algorithms_server_to_client = SupportedMACs;
      return kexInit;
    },
  }),
  [](auto& info) {
    return (std::array{
              "SameAeadEmptyMac",
              "SameAeadMacUnused",
              "SameEtmAndMac",
              "AeadClientToServerAndEtmServerToClient",
              "EtmClientToServerAndAeadServerToClient",
              "DifferentEtmAndMac",
              "DifferentAeadMacUnused",
              "AeadClientToServerAndEtmServerToClientWithMultipleSupportedAlgs",
            })
      .at(info.index);
  });

class ClientKexTest : public BaseKexTest {
public:
  enum SuspensionPoint {
    Begin,
    BeforeClientKexInitSent,
    AfterClientKexInitSent,
    BeforeServerKexInitSent,
    AfterServerKexInitSent,
    BeforeServerEcdhReplySent,
    AfterServerEcdhReplySent,
    BeforeServerNewKeysSent,
    AfterServerNewKeysSent,

    DoInitiateRekey = 99,
  };

  ClientKexTest()
      : BaseKexTest(startKexSequence(normal_server_kex_init_msg)) {
  }

  void SetUp() override {
    kex_ = std::make_unique<Kex>(*transport_callbacks_, *kex_callbacks_, algorithm_factories_, cipher_factories_, KexMode::Client);
    auto&& [hostKeys, hostKeyBlobs] = newServerHostKeys();
    kex_->setHostKeys(std::move(hostKeys));
    host_key_blobs_ = std::move(hostKeyBlobs);
    kex_->setVersionStrings("SSH-2.0-Client", "SSH-2.0-Server");
    kex_->registerMessageHandlers(*peer_reply_);
  }

protected:
  std::optional<bool> server_supports_ext_info_;
  std::unordered_map<std::string, bytes> host_key_blobs_; // alg->blob

  KexSequence startKexSequence(wire::KexInitMsg server_kex_init, bool initial_kex = true) {
    // ensure all expected calls are ordered
    IN_SEQUENCE;

    // KexInit
    co_yield BeforeClientKexInitSent;
    if (!sequence.expecting_error_) {
      EXPECT_CALL(*kex_callbacks_, onKexInitMsgSent());
      EXPECT_CALL(*transport_callbacks_, sendMessageDirect(MSG(wire::KexInitMsg, _)))
        .WillOnce(Invoke([&](wire::Message&& msg) -> absl::StatusOr<size_t> {
          EXPECT_EQ(wire::KexInitMsg::type, msg.msg_type());
          sequence.client_kex_init_ = msg.message.get<wire::KexInitMsg>();
          return 0;
        }));
      EXPECT_CALL(*kex_callbacks_, onKexStarted(initial_kex));
    }
    if (auto stat = kex_->initiateKex(); !stat.ok()) {
      co_return stat;
    }
    co_yield AfterClientKexInitSent;

    sequence.server_kex_init_ = server_kex_init;
    co_yield BeforeServerKexInitSent;
    if (!sequence.expecting_error_) {
      EXPECT_CALL(*transport_callbacks_, sendMessageDirect(MSG(wire::KexEcdhInitMsg, _)))
        .WillOnce(Invoke([&](wire::Message&& msg) -> absl::StatusOr<size_t> {
          EXPECT_EQ(wire::KexEcdhInitMsg::type, msg.msg_type());
          msg.visit(
            [&](opt_ref<wire::KexEcdhInitMsg> msg) {
              sequence.client_ecdh_init_ = msg.value();
            },
            [](auto&) {
              FAIL();
            });
          return 0;
        }));
    }
    if (auto stat = peer_reply_->dispatch(auto(sequence.server_kex_init_)); !stat.ok()) {
      co_return stat;
    }
    co_yield AfterServerKexInitSent;

    HandshakeMagics magics{
      .client_version = "SSH-2.0-Client",
      .server_version = "SSH-2.0-Server",
      .client_kex_init = *encodeTo<bytes>(sequence.client_kex_init_),
      .server_kex_init = *encodeTo<bytes>(sequence.server_kex_init_),
    };
    auto& pendingState = kex_->getPendingStateForTest();

    auto alg = algorithm_factories_
                 .factoryForName(pendingState.negotiated_algorithms.kex)
                 ->create(&magics, &pendingState.negotiated_algorithms,
                          kex_->pickHostKey(pendingState.negotiated_algorithms.host_key));

    wire::Message tmp{sequence.client_ecdh_init_};
    auto result = alg->handleServerRecv(tmp);
    if (!result.ok()) {
      co_return result.status();
    }
    sequence.server_kex_result_ = **result;
    // some fields aren't filled by handleClientRecv, so set them to the expected values
    if (initial_kex) {
      sequence.server_kex_result_->session_id = sequence.server_kex_result_->exchange_hash;
      session_id_ = sequence.server_kex_result_->session_id;
    } else {
      sequence.server_kex_result_->session_id = session_id_.value();
    }
    sequence.server_kex_result_->client_supports_ext_info = true;
    if (initial_kex) {
      sequence.server_kex_result_->server_supports_ext_info = absl::c_contains(*sequence.server_kex_init_.kex_algorithms, "ext-info-s");
      server_supports_ext_info_ = sequence.server_kex_result_->server_supports_ext_info;
    } else {
      sequence.server_kex_result_->server_supports_ext_info = server_supports_ext_info_.value();
    }

    co_yield BeforeServerEcdhReplySent;
    if (!sequence.expecting_error_) {
      EXPECT_CALL(*transport_callbacks_, sendMessageDirect(MSG(wire::NewKeysMsg, _)))
        .WillOnce(Invoke([&](wire::Message&& msg) -> absl::StatusOr<size_t> {
          EXPECT_EQ(wire::NewKeysMsg::type, msg.msg_type());
          return 0;
        }));
      EXPECT_CALL(*transport_callbacks_, resetWriteSequenceNumber())
        .WillOnce(Return(3)); // KexInitMsg, KexEcdhReplyMsg, NewKeysMsg
    }

    if (auto stat = peer_reply_->dispatch(alg->buildServerReply(*sequence.server_kex_result_)); !stat.ok()) {
      co_return stat;
    }
    co_yield AfterServerEcdhReplySent;

    // NewKeys
    co_yield BeforeServerNewKeysSent;
    DiscardHandler<wire::IgnoreMsg> ignoreHandler;
    if (!sequence.expecting_error_) {
      EXPECT_CALL(*transport_callbacks_, resetReadSequenceNumber())
        .WillOnce(Return(3)); // KexInitMsg, KexEcdhInitMsg, NewKeysMsg
      EXPECT_CALL(*kex_callbacks_, onKexCompleted(_, initial_kex))
        .WillOnce(DoAll(SaveArg<0>(&sequence.client_kex_result_), [&] {
          ignoreHandler.registerMessageHandlers(*peer_reply_);
        }));
    }
    if (auto stat = peer_reply_->dispatch(wire::Message{wire::NewKeysMsg{}}); !stat.ok()) {
      co_return stat;
    }
    co_yield AfterServerNewKeysSent;

    // Done
    EXPECT_EQ(*sequence.client_kex_result_, *sequence.server_kex_result_);

    peer_reply_->unregisterHandler(&ignoreHandler);
    co_return absl::OkStatus();
  }
};

TEST_F(ClientKexTest, BasicKeyExchange) {
  ContinueUntilEnd();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec