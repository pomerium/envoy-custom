#include "source/extensions/filters/network/ssh/transport_base.h"
#include "gtest/gtest.h"
#include <latch>
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h" // IWYU pragma: keep
#include "test/extensions/filters/network/ssh/test_mocks.h"              // IWYU pragma: keep
#include "test/test_common/test_common.h"
#include "test/test_common/utility.h"
#include "absl/synchronization/notification.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {
// NOLINTBEGIN(readability-identifier-naming)
template <typename T>
class MockBaseTransport : public TransportBase<T> {
public:
  MockBaseTransport(Api::Api& api,
                    std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
      : TransportBase<T>(api, config),
        dispatcher_(api.allocateDispatcher(std::string(codec_traits<T>::name))) {
    SetVersion(fmt::format("SSH-2.0-{}", codec_traits<T>::name));
  }

  void setupDefaultMocks() {
    RELEASE_ASSERT(dispatcher_->isThreadSafe(), "test bug: not thread-safe");
    ON_CALL(*this, onKexStarted(_))
      .WillByDefault([this](bool initial) {
        return this->TransportBase<T>::onKexStarted(initial);
      });
    ON_CALL(*this, onKexInitMsgSent())
      .WillByDefault([this]() {
        return this->TransportBase<T>::onKexInitMsgSent();
      });
    ON_CALL(*this, onKexCompleted(_, _))
      .WillByDefault([this](std::shared_ptr<KexResult> result, bool initial) {
        return this->TransportBase<T>::onKexCompleted(result, initial);
      });
    ON_CALL(*this, onVersionExchangeCompleted(_, _, _))
      .WillByDefault([this](const bytes& server_version, const bytes& client_version, const bytes& banner) {
        return this->TransportBase<T>::onVersionExchangeCompleted(server_version, client_version, banner);
      });
    ON_CALL(*this, onMessageDecoded(_))
      .WillByDefault([this](wire::Message&& msg) {
        return this->TransportBase<T>::onMessageDecoded(std::move(msg));
      });
    ON_CALL(*this, sendMessageToConnection(_))
      .WillByDefault([this](wire::Message&& msg) {
        return this->TransportBase<T>::sendMessageToConnection(std::move(msg));
      });
    ON_CALL(*this, sendMessageDirect(_))
      .WillByDefault([this](wire::Message&& msg) {
        return this->TransportBase<T>::sendMessageDirect(std::move(msg));
      });
    ON_CALL(*this, updatePeerExtInfo(_))
      .WillByDefault([this](std::optional<wire::ExtInfoMsg> msg) {
        return this->TransportBase<T>::updatePeerExtInfo(std::move(msg));
      });
    ON_CALL(*this, registerMessageHandlers(_))
      .WillByDefault([this](SshMessageDispatcher& dispatcher) {
        dispatcher.registerHandler(wire::SshMessageType::Debug, this);
        dispatcher.registerHandler(wire::SshMessageType::Ignore, this);
        dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);
      });
    ON_CALL(*this, streamId)
      .WillByDefault(Return(1));
  }

  void setCodecCallbacks(codec_traits<T>::callbacks_type& callbacks) override {
    TransportBase<T>::setCodecCallbacks(callbacks);
    this->kex_->setHostKeys(*openssh::loadHostKeys(this->codecConfig().host_keys()));
  }

  using TransportBase<T>::outgoingExtInfo;
  using TransportBase<T>::peerExtInfo;
  using TransportBase<T>::seq_read_;
  using TransportBase<T>::seq_write_;
  using TransportBase<T>::cipher_;
  using TransportBase<T>::read_bytes_remaining_;
  using TransportBase<T>::write_bytes_remaining_;
  using TransportBase<T>::pending_key_exchange_;

  MOCK_METHOD(void, updatePeerExtInfo, (std::optional<wire::ExtInfoMsg>), (override));                   // delegates to the base class
  MOCK_METHOD(void, onKexStarted, (bool), (override));                                                   // delegates to the base class
  MOCK_METHOD(void, onKexInitMsgSent, (), (override));                                                   // delegates to the base class
  MOCK_METHOD(void, onKexCompleted, (std::shared_ptr<KexResult>, bool), (override));                     // delegates to the base class
  MOCK_METHOD(void, onVersionExchangeCompleted, (const bytes&, const bytes&, const bytes&), (override)); // delegates to the base class
  MOCK_METHOD(absl::Status, onMessageDecoded, (wire::Message&&), (override));                            // delegates to the base class
  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageToConnection, (wire::Message&&), (override));           // delegates to the base class
  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageDirect, (wire::Message&&), (override));                 // delegates to the base class

  MOCK_METHOD(EncodingResult, encode, (const StreamFrame&, EncodingContext&));                         // pure virtual, not tested here
  MOCK_METHOD(ResponseHeaderFramePtr, respond, (Status, std::string_view, const RequestHeaderFrame&)); // pure virtual, not tested here

  MOCK_METHOD(absl::Status, handleMessage, (wire::Message&&));         // pure virtual, used for assertions
  MOCK_METHOD(void, registerMessageHandlers, (SshMessageDispatcher&)); // mocked

  MOCK_METHOD(void, forward, (wire::Message&&, FrameTags));                   // pure virtual, not tested here
  MOCK_METHOD(absl::StatusOr<bytes>, signWithHostKey, (bytes_view), (const)); // pure virtual, not tested here
  MOCK_METHOD(const AuthState&, authState, (), (const));                      // pure virtual, not tested here
  MOCK_METHOD(AuthState&, authState, ());                                     // pure virtual, not tested here
  MOCK_METHOD(stream_id_t, streamId, (), (const));                            // mocked

  void SetOutgoingExtInfo(wire::ExtInfoMsg&& msg) {
    this->outgoing_ext_info_ = std::move(msg);
  }

  auto StartThread(absl::Duration timeout) {
    ASSERT_IS_TEST_THREAD();
    auto opts = Thread::Options{.name_ = fmt::format("{} thread", codec_traits<T>::name)};
    return this->api_.threadFactory().createThread(
      [this, timeout] {
        setupDefaultMocks();
        auto timer = dispatcher_->createTimer([this] {
          RELEASE_ASSERT(dispatcher_->isThreadSafe(), "test bug: not thread-safe");
          Exit();
          ADD_FAILURE() << "timeout";
        });
        timer->enableTimer(absl::ToChronoMilliseconds(timeout));
        dispatcher_->run(::Envoy::Event::Dispatcher::RunType::RunUntilExit);
        timer->disableTimer();
      },
      opts);
  }

  size_t InitiateVersionExchange() {
    RELEASE_ASSERT(dispatcher_->isThreadSafe(), "test bug: not thread-safe");
    return this->version_exchanger_->writeVersion(this->server_version_);
  }

  absl::Status InitiateRekey() {
    RELEASE_ASSERT(dispatcher_->isThreadSafe(), "test bug: not thread-safe");
    return this->kex_->initiateKex();
  }

  void Exit() {
    closed_ = true;
    if (!dispatcher_->isThreadSafe()) {
      dispatcher_->post([this] {
        this->Exit();
      });
    } else {
      dispatcher_->exit();
    }
  }

  template <typename F>
    requires std::is_void_v<callable_arg_type_t<F>>
  void Post(F fn) {
    dispatcher_->post([this, fn] {
      if (closed_) {
        return;
      }
      fn();
    });
  }

  template <typename F>
    requires std::is_invocable_v<F, MockBaseTransport<T>&>
  void Post(F fn) {
    dispatcher_->post([this, fn = std::move(fn)] mutable {
      if (closed_) {
        return;
      }
      fn(*this);
    });
  }

  void SetVersion(std::string_view version) {
    this->server_version_ = version;
  }

private:
  std::atomic_bool closed_{false};
  ::Envoy::Event::DispatcherPtr dispatcher_;
};

inline absl::Duration defaultTimeout() {
  if (isDebuggerAttached()) {
    return absl::Hours(1);
  }
  return absl::Seconds(10);
}

template <typename TestOptions>
class TransportBaseTest : public testing::Test {
public:
  TransportBaseTest()
      : api_(Api::createApiForTest()),
        server_config_(std::make_shared<pomerium::extensions::ssh::CodecConfig>()),
        client_config_(std::make_shared<pomerium::extensions::ssh::CodecConfig>()),
        server_transport_(*api_, [this] {
          for (auto keyName : {"rsa_1", "ed25519_1"}) {
            server_config_->add_host_keys()->set_filename(copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600));
          }
          return server_config_;
        }()),
        client_transport_(*api_, [this] {
          for (auto keyName : {"rsa_2", "ed25519_2"}) {
            client_config_->add_host_keys()->set_filename(copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600));
          }
          return client_config_;
        }()) {}

  void SetUp() override {
    // wire up the transports to send data to each other; each transport runs its own dispatcher on
    // a separate thread.
    ON_CALL(server_codec_callbacks_, writeToConnection)
      .WillByDefault(Invoke([&](Envoy::Buffer::Instance& input) {
        Buffer::OwnedImpl buffer;
        buffer.move(input);
        client_transport_.Post([buffer = std::move(buffer)](auto& self) mutable {
          self.decode(buffer, false);
        });
      }));
    ON_CALL(client_codec_callbacks_, writeToConnection)
      .WillByDefault(Invoke([&](Envoy::Buffer::Instance& input) {
        Buffer::OwnedImpl buffer;
        buffer.move(input);
        server_transport_.Post([buffer = std::move(buffer)](auto& self) mutable {
          self.decode(buffer, false);
        });
      }));
    EXPECT_CALL(server_codec_callbacks_, writeToConnection).Times(AnyNumber());
    EXPECT_CALL(client_codec_callbacks_, writeToConnection).Times(AnyNumber());
    server_transport_.setCodecCallbacks(server_codec_callbacks_);
    client_transport_.setCodecCallbacks(client_codec_callbacks_);
  }

  void Start() {
    auto timeout = defaultTimeout();
    server_thread_ = server_transport_.StartThread(timeout);
    client_thread_ = client_transport_.StartThread(timeout);
  }

  void Join() {
    server_thread_->join();
    client_thread_->join();
  }

  // the terms "client" and "server" here are not really accurate - it's more like "initiator" and
  // "non-initiator" but that is too verbose/error-prone to write.
  auto& Client() {
    if constexpr (TestOptions::client_initiates) {
      return client_transport_;
    } else {
      return server_transport_;
    }
  }

  auto& Server() {
    if constexpr (TestOptions::client_initiates) {
      return server_transport_;
    } else {
      return client_transport_;
    }
  }

  auto& ClientCallbacks() {
    if constexpr (TestOptions::client_initiates) {
      return client_codec_callbacks_;
    } else {
      return server_codec_callbacks_;
    }
  }

  auto& ServerCallbacks() {
    if constexpr (TestOptions::client_initiates) {
      return server_codec_callbacks_;
    } else {
      return client_codec_callbacks_;
    }
  }
  auto& ClientConfig() {
    if constexpr (TestOptions::client_initiates) {
      return *client_config_;
    } else {
      return *server_config_;
    }
  }

  auto& ServerConfig() {
    if constexpr (TestOptions::client_initiates) {
      return *server_config_;
    } else {
      return *client_config_;
    }
  }

  void InitiateVersionExchange() {
    // The constraint that the client initiates the handshake doesn't apply at this abstraction level
    Client().Post([](auto& t) {
      t.InitiateVersionExchange();
    });
  }

  void VerifyAndClearExpectations() {
    testing::Mock::VerifyAndClearExpectations(&server_transport_);
    testing::Mock::VerifyAndClearExpectations(&client_transport_);
    testing::Mock::VerifyAndClearExpectations(&server_codec_callbacks_);
    testing::Mock::VerifyAndClearExpectations(&client_codec_callbacks_);

    // restore the writeToConnection expectations, which are exceptions to the strict mock
    EXPECT_CALL(server_codec_callbacks_, writeToConnection).Times(AnyNumber());
    EXPECT_CALL(client_codec_callbacks_, writeToConnection).Times(AnyNumber());
  }

  // Setup code used in key re-exchange tests
  bool StartAndWaitForInitialKeyExchange() {
    EXPECT_CALL(this->Client(), onKexStarted(true));
    EXPECT_CALL(this->Server(), onKexStarted(true));

    absl::Notification serverKexCompleted;
    absl::Notification clientKexCompleted;

    EXPECT_CALL(this->Client(), onKexCompleted(_, true))
      .WillOnce(Invoke([this, &clientKexCompleted](std::shared_ptr<KexResult> result, bool initial) {
        this->Client().TransportBase::onKexCompleted(result, initial);
        clientKexCompleted.Notify();
      }));
    EXPECT_CALL(this->Server(), onKexCompleted(_, true))
      .WillOnce(Invoke([this, &serverKexCompleted](std::shared_ptr<KexResult> result, bool initial) {
        this->Server().TransportBase::onKexCompleted(result, initial);
        serverKexCompleted.Notify();
      }));

    this->Start();
    this->InitiateVersionExchange();

    if (!serverKexCompleted.WaitForNotificationWithTimeout(defaultTimeout())) {
      ADD_FAILURE() << "timed out waiting for server key exchange";
      return false;
    }
    if (!clientKexCompleted.WaitForNotificationWithTimeout(defaultTimeout())) {
      ADD_FAILURE() << "timed out waiting for client key exchange";
      return false;
    }

    this->VerifyAndClearExpectations();
    return true;
  }

protected:
  Api::ApiPtr api_;
  Thread::ThreadPtr server_thread_;
  Thread::ThreadPtr client_thread_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> server_config_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> client_config_;
  testing::NiceMock<MockBaseTransport<ServerCodec>> server_transport_;
  testing::NiceMock<MockBaseTransport<ClientCodec>> client_transport_;
  testing::StrictMock<MockServerCodecCallbacks> server_codec_callbacks_;
  testing::StrictMock<MockClientCodecCallbacks> client_codec_callbacks_;
  openssh::SSHKeyPtr client_auth_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
};
// NOLINTEND(readability-identifier-naming)

struct ClientInitiatesOptions {
  static constexpr bool client_initiates = true;
};
struct ServerInitiatesOptions {
  static constexpr bool client_initiates = false;
};
using transportBaseTestTypes = testing::Types<ClientInitiatesOptions, ServerInitiatesOptions>;

TYPED_TEST_SUITE(TransportBaseTest, transportBaseTestTypes);

TYPED_TEST(TransportBaseTest, TestHandshake) {
  EXPECT_CALL(this->Client(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexStarted(true));

  KexResultSharedPtr clientKexResult;
  KexResultSharedPtr serverKexResult;
  EXPECT_CALL(this->Client(), onKexCompleted(_, true))
    .WillOnce(DoAll(SaveArg<0>(&clientKexResult),
                    Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
                      this->Client().TransportBase::onKexCompleted(result, initial);
                      this->Client().Exit();
                    })));
  EXPECT_CALL(this->Server(), onKexCompleted(_, true))
    .WillOnce(DoAll(SaveArg<0>(&serverKexResult),
                    Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
                      this->Server().TransportBase::onKexCompleted(result, initial);
                      this->Server().Exit();
                    })));

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
  EXPECT_EQ(*clientKexResult, *serverKexResult);
  EXPECT_EQ(this->Client().sessionId(), clientKexResult->session_id);
  EXPECT_EQ(this->Server().sessionId(), serverKexResult->session_id);
}

TYPED_TEST(TransportBaseTest, TestHandshakeWithExtInfo) {
  wire::ExtInfoMsg info;
  info.extensions->emplace_back(wire::PingExtension{.version = "0"s});
  this->Client().SetOutgoingExtInfo(auto(info));
  this->Server().SetOutgoingExtInfo(auto(info));

  EXPECT_CALL(this->Client(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexStarted(true));

  EXPECT_CALL(this->Client(), updatePeerExtInfo(_))
    .WillOnce(Invoke([this](std::optional<wire::ExtInfoMsg> msg) {
      this->Client().TransportBase::updatePeerExtInfo(std::move(msg));
      this->Client().Exit();
    }));
  EXPECT_CALL(this->Server(), updatePeerExtInfo(_))
    .WillOnce(Invoke([this](std::optional<wire::ExtInfoMsg> msg) {
      this->Server().TransportBase::updatePeerExtInfo(std::move(msg));
      this->Server().Exit();
    }));
  EXPECT_CALL(this->Client(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      EXPECT_OK(this->Client().sendMessageToConnection(*this->Client().outgoingExtInfo()).status());
    }));
  EXPECT_CALL(this->Server(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->Server().TransportBase::onKexCompleted(result, initial);
      EXPECT_OK(this->Server().sendMessageToConnection(*this->Server().outgoingExtInfo()).status());
    }));

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
  EXPECT_EQ(info, this->Client().peerExtInfo());
  EXPECT_EQ(info, this->Server().peerExtInfo());
  EXPECT_EQ(std::nullopt, this->Client().outgoingExtInfo());
  EXPECT_EQ(std::nullopt, this->Server().outgoingExtInfo());
}

TYPED_TEST(TransportBaseTest, TestVersionExchange_InvalidVersion) {
  EXPECT_CALL(this->ServerCallbacks(), onDecodingFailure("version string contains invalid characters"sv))
    .WillOnce([this](std::string_view) {
      this->Client().Exit();
      this->Server().Exit();
    });
  this->Client().SetVersion("SSH-2.0--");

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestVersionExchangeIncomplete) {
  EXPECT_CALL(this->ClientCallbacks(), writeToConnection)
    .WillOnce(Invoke([&](Envoy::Buffer::Instance& input) {
      // send two buffers,
      Buffer::OwnedImpl buffer1; // "SSH-2.0-"
      buffer1.add(input.linearize(input.length()), input.length() / 2);
      Buffer::OwnedImpl buffer2; // "SSH-2.0-aaaaaa\r\n"
      buffer2.move(input);
      this->Server().Post([buffer = std::move(buffer1)](auto& self) mutable {
        self.decode(buffer, false);
      });
      this->Server().Post([buffer = std::move(buffer2)](auto& self) mutable {
        self.decode(buffer, false);
      });
    }));
  EXPECT_CALL(this->Client(), onVersionExchangeCompleted)
    .WillOnce(InvokeWithoutArgs([this] {
      this->Client().Exit();
    }));
  EXPECT_CALL(this->Server(), onVersionExchangeCompleted)
    .WillOnce(InvokeWithoutArgs([this] {
      this->Server().Exit();
    }));
  this->Client().SetVersion("SSH-2.0-aaaaaa");

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestKexInitFailureAfterVersionExchange) {
  EXPECT_CALL(this->Client(), onVersionExchangeCompleted)
    .WillOnce(InvokeWithoutArgs([this] {
      this->Client().Exit();
    }));
  EXPECT_CALL(this->Server(), onVersionExchangeCompleted)
    .WillOnce(Invoke([this](const bytes& server_version, const bytes& client_version, const bytes& banner) {
      // the next KexInitMsg sent by the server will return an error
      IN_SEQUENCE;
      EXPECT_CALL(this->Server(), sendMessageDirect(MSG(wire::KexInitMsg, _)))
        .WillOnce(InvokeWithoutArgs([] {
          return absl::InternalError("test error");
        }));
      EXPECT_CALL(this->ServerCallbacks(), onDecodingFailure(HasSubstr("test error"s)))
        .WillOnce(InvokeWithoutArgs([this] {
          this->Server().Exit();
        }));
      // complete the version exchange, triggering the KexInitMsg to be sent
      return this->Server().TransportBase::onVersionExchangeCompleted(server_version, client_version, banner);
    }));
  this->Client().SetVersion("SSH-2.0-test");
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestDecryptPacketFailure) {
  EXPECT_CALL(this->Client(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexStarted(true));
  EXPECT_CALL(this->Client(), onKexCompleted(_, true));
  EXPECT_CALL(this->Server(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->Server().TransportBase::onKexCompleted(result, initial);
      this->Client().Post([this](auto& self) {
        // change the receiver's sequence number, so they will fail to decrypt the packet
        self.seq_read_++;
        // then send them a message
        this->Server().Post([](auto& server) {
          EXPECT_OK(server.sendMessageToConnection(wire::Message{wire::DebugMsg{}}).status());
          server.Exit();
        });
      });
    }));

  EXPECT_CALL(this->ClientCallbacks(), onDecodingFailure(HasSubstr("failed to decrypt packet"s)))
    .WillOnce(InvokeWithoutArgs([this] {
      this->Client().Exit();
    }));
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestReadIncompletePacket) {
  EXPECT_CALL(this->Client(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexCompleted(_, true));

  wire::Message expectedMsg{wire::IgnoreMsg{.data = "foo"_bytes}};
  EXPECT_CALL(this->Client(), onKexCompleted(_, true))
    .WillOnce(Invoke([this, expectedMsg](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      IN_SEQUENCE;
      EXPECT_CALL(this->ClientCallbacks(), writeToConnection)
        .WillOnce(Invoke([this](Envoy::Buffer::Instance& input) {
          // Hijack the writeToConnection callback to send two packets: the first containing
          // half of the full input, and the second containing the full input. The server should
          // recognize that the first packet is incomplete, then wait for the second one before
          // decoding the message. Note that it will NOT drain the input buffer for incomplete
          // packets, so the second packet is not just the second half of the input.
          Buffer::OwnedImpl buffer1;
          buffer1.add(input.linearize(input.length()), input.length() / 2);
          Buffer::OwnedImpl buffer2;
          buffer2.move(input);
          this->Server().Post([buffer = std::move(buffer1)](auto& server) mutable {
            // first packet (no callbacks expected)
            auto bufferLen = buffer.length();
            server.decode(buffer, false);
            EXPECT_EQ(bufferLen, buffer.length()); // the buffer should not be drained
          });
          this->Server().Post([buffer = std::move(buffer2)](auto& server) mutable {
            // second packet with the full message, expect the message to be decoded now
            EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, Eq(wire::IgnoreMsg{.data = "foo"_bytes}))))
              .WillOnce(Invoke([&server](wire::Message&&) {
                server.Exit();
                return absl::OkStatus();
              }));
            server.decode(buffer, false);
            EXPECT_EQ(0, buffer.length());
          });
        }));
      EXPECT_OK(this->Client().sendMessageToConnection(auto(expectedMsg)).status());
      this->Client().Exit();
    }));
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestDecodePacketFailure) {
  EXPECT_CALL(this->Client(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      EXPECT_CALL(this->ServerCallbacks(), onDecodingFailure("failed to decode packet: invalid padding length"sv))
        .WillOnce(InvokeWithoutArgs([this] {
          this->Server().Exit();
          this->Client().Exit();
        }));

      Buffer::OwnedImpl badPacket;
      auto msg = wire::Message{wire::IgnoreMsg{.data = "foo"_bytes}};
      ASSERT_OK(wire::encodePacket(badPacket, msg,
                                   this->Client().cipher_->blockSize(openssh::CipherMode::Write),
                                   this->Client().cipher_->aadSize(openssh::CipherMode::Write))
                  .status());
      // poke 0 in for the padding length, which will cause an error when decoding
      unsafe_forge_span(static_cast<uint8_t*>(badPacket.linearize(5)), 5).back() = 0;
      // encrypt the packet
      Buffer::OwnedImpl enc;
      ASSERT_OK(this->Client().cipher_->encryptPacket(this->Client().seq_write_++, enc, badPacket));
      // send to server
      this->ClientCallbacks().writeToConnection(enc);
    }));
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestDecodeMessageFailure) {
  EXPECT_CALL(this->Client(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexCompleted(_, true));

  wire::Message expectedMsg{wire::IgnoreMsg{.data = "foo"_bytes}};
  EXPECT_CALL(this->Client(), onKexCompleted(_, true))
    .WillOnce(Invoke([this, expectedMsg](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);

      this->Server().Post([this](auto& server) {
        IN_SEQUENCE;
        EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, Eq(wire::IgnoreMsg{.data = "foo"_bytes}))))
          .WillOnce(Invoke([](wire::Message&&) {
            // simulate an error in the handler for this message
            return absl::InternalError("test error");
          }));
        // this should call onDecodingFailure
        EXPECT_CALL(this->ServerCallbacks(), onDecodingFailure(HasSubstr("test error"s)))
          .WillOnce(InvokeWithoutArgs([this] {
            this->Server().Exit();
            this->Client().Exit();
          }));
      });
      EXPECT_OK(this->Client().sendMessageToConnection(auto(expectedMsg)).status());
    }));
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, OnDecodingFailure) {
  EXPECT_CALL(this->ClientCallbacks(), onDecodingFailure("test error"));
  this->Client().onDecodingFailure(absl::InternalError("test error"));

  EXPECT_CALL(this->ClientCallbacks(), onDecodingFailure(""));
  this->Client().onDecodingFailure(absl::OkStatus());
}

TYPED_TEST(TransportBaseTest, TestRekeyManual) {
  EXPECT_CALL(this->Client(), onKexStarted(true));
  EXPECT_CALL(this->Server(), onKexStarted(true));

  std::latch wait{2};
  EXPECT_CALL(this->Client(), onKexCompleted(_, true))
    .WillOnce(Invoke([this, &wait](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      wait.count_down();
    }));
  EXPECT_CALL(this->Server(), onKexCompleted(_, true))
    .WillOnce(Invoke([this, &wait](std::shared_ptr<KexResult> result, bool initial) {
      this->Server().TransportBase::onKexCompleted(result, initial);
      wait.count_down();
    }));

  this->Start();
  this->InitiateVersionExchange();

  wait.wait();
  this->VerifyAndClearExpectations();

  EXPECT_CALL(this->Client(), onKexStarted(false));
  EXPECT_CALL(this->Server(), onKexStarted(false));
  EXPECT_CALL(this->Client(), onKexCompleted(_, false))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      this->Client().Exit();
    }));
  EXPECT_CALL(this->Server(), onKexCompleted(_, false))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->Server().TransportBase::onKexCompleted(result, initial);
      this->Server().Exit();
    }));

  this->Client().Post([](auto& self) {
    EXPECT_OK(self.InitiateRekey());
  });
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestRekeyWithQueuedMessages) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  absl::Notification serverDone{};
  absl::Notification clientDone{};

  this->Client().Post([&clientDone](auto& client) {
    // Each of these sequences is thread-local, so there are two separate sequences set up on
    // each peer's respective thread.
    // Note: "this->Client()" can be either the server or client transport, so the order of the
    // KexEcdh messages is slightly different.
    IN_SEQUENCE;
    /*C->S*/ EXPECT_CALL(client, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server unqueued message 1"s))));
    /*C->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server unqueued message 1"s))));
    /*C->S*/ EXPECT_CALL(client, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server unqueued message 2"s))));
    /*C->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server unqueued message 2"s))));
    /*C->|*/ EXPECT_CALL(client, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server queued message 1"s))));
    /*C->|*/ EXPECT_CALL(client, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server queued message 2"s))));
    /*C->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _)));
    /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client unqueued message 1"s))));
    /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client unqueued message 2"s))));
    /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexInitMsg, _)));
    EXPECT_CALL(client, onKexStarted(false));
    if constexpr (TypeParam::client_initiates) {
      /*C->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexEcdhInitMsg, _)));
      /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexEcdhReplyMsg, _)));
    } else {
      /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexEcdhInitMsg, _)));
      /*C->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexEcdhReplyMsg, _)));
    }
    /*C->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::NewKeysMsg, _)));
    /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::NewKeysMsg, _)));
    EXPECT_CALL(client, onKexCompleted(_, false));
    /*|->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server queued message 1"s))));
    /*|->S*/ EXPECT_CALL(client, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server queued message 2"s))));
    /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client queued message 1"s))));
    /*C<-S*/ EXPECT_CALL(client, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client queued message 2"s))))
      .WillOnce(InvokeWithoutArgs([&clientDone] mutable {
        clientDone.Notify();
        return absl::OkStatus();
      }));
  });

  this->Server().Post([&serverDone](auto& server) {
    IN_SEQUENCE;
    /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server unqueued message 1"s))));
    /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server unqueued message 2"s))));
    /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexInitMsg, _)));
    EXPECT_CALL(server, onKexStarted(false));
    /*S->C*/ EXPECT_CALL(server, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client unqueued message 1"s))));
    /*S->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client unqueued message 1"s))));
    /*S->C*/ EXPECT_CALL(server, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client unqueued message 2"s))));
    /*S->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client unqueued message 2"s))));
    /*S->|*/ EXPECT_CALL(server, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client queued message 1"s))));
    /*S->|*/ EXPECT_CALL(server, sendMessageToConnection(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client queued message 2"s))));
    /*S->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexInitMsg, _)));
    if constexpr (TypeParam::client_initiates) {
      /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexEcdhInitMsg, _)));
      /*S->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexEcdhReplyMsg, _)));
    } else {
      /*S<-C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexEcdhInitMsg, _)));
      /*S->C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexEcdhReplyMsg, _)));
    }
    /*S->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::NewKeysMsg, _)));
    /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::NewKeysMsg, _)));
    EXPECT_CALL(server, onKexCompleted(_, false));
    /*|->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client queued message 1"s))));
    /*|->C*/ EXPECT_CALL(server, sendMessageDirect(MSG(wire::DebugMsg, FIELD_EQ(message, "server->client queued message 2"s))));
    /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server queued message 1"s))));
    /*S<-C*/ EXPECT_CALL(server, onMessageDecoded(MSG(wire::DebugMsg, FIELD_EQ(message, "client->server queued message 2"s))))
      .WillOnce(InvokeWithoutArgs([&serverDone] mutable {
        serverDone.Notify();
        return absl::OkStatus();
      }));
  });

  EXPECT_CALL(this->Client(), onKexInitMsgSent())
    .WillOnce(InvokeWithoutArgs([this] {
      // sneak in messages before our KexInit (this callback fires before actually sending it)
      // to check that that they are not queued since they are sent before our KexInit.
      ASSERT_OK(this->Client().sendMessageToConnection(wire::DebugMsg{.message = "client->server unqueued message 1"s}).status());
      ASSERT_OK(this->Client().sendMessageToConnection(wire::DebugMsg{.message = "client->server unqueued message 2"s}).status());

      // Calling the base class onKexInitMsgSent is important here - it sets the flag that causes
      // newly-sent messages to become queued. Note that onKexStarted(false) signals something
      // else entirely: that the peer has sent their KexInit message, and we must not allow anything
      // else from them other than key-exchange related messages until they send NewKeys. We can
      // receive any messages from the peer after sending our own KexInit (starting the re-exchange)
      // until receiving their KexInit.
      this->Client().TransportBase::onKexInitMsgSent();

      // after starting the re-exchange on the client side, send a couple messages
      // these should only be queued, not sent - the matching EXPECT_CALLs occur below
      ASSERT_OK(this->Client().sendMessageToConnection(wire::DebugMsg{.message = "client->server queued message 1"s}).status());
      ASSERT_OK(this->Client().sendMessageToConnection(wire::DebugMsg{.message = "client->server queued message 2"s}).status());
    }));
  EXPECT_CALL(this->Server(), onKexInitMsgSent())
    .WillOnce(InvokeWithoutArgs([this] {
      // same sequence on the server

      ASSERT_OK(this->Server().sendMessageToConnection(wire::DebugMsg{.message = "server->client unqueued message 1"s}).status());
      ASSERT_OK(this->Server().sendMessageToConnection(wire::DebugMsg{.message = "server->client unqueued message 2"s}).status());

      this->Server().TransportBase::onKexInitMsgSent();

      ASSERT_OK(this->Server().sendMessageToConnection(wire::DebugMsg{.message = "server->client queued message 1"s}).status());
      ASSERT_OK(this->Server().sendMessageToConnection(wire::DebugMsg{.message = "server->client queued message 2"s}).status());
    }));

  this->Client().Post([](auto& self) {
    EXPECT_OK(self.InitiateRekey());
  });

  // verify the queued messages have been received
  if (!serverDone.WaitForNotificationWithTimeout(defaultTimeout())) {
    ADD_FAILURE() << "timed out waiting for server to receive queued messages";
  }
  if (!clientDone.WaitForNotificationWithTimeout(defaultTimeout())) {
    ADD_FAILURE() << "timed out waiting for server to receive queued messages";
  }
  this->Server().Exit();
  this->Client().Exit();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestDisconnectAlwaysSentDuringRekey) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  EXPECT_CALL(this->Client(), onKexInitMsgSent())
    .WillOnce(InvokeWithoutArgs([this] {
      ASSERT_FALSE(this->Client().pending_key_exchange_); // sanity check
      this->Client().TransportBase::onKexInitMsgSent();
      ASSERT_TRUE(this->Client().pending_key_exchange_); // sanity check

      // the disconnect should be sent immediately, even though we are calling
      // sendMessageToConnection during a key exchange.
      ASSERT_OK(this->Client().sendMessageToConnection(wire::DisconnectMsg{}).status());
    }));
  EXPECT_CALL(this->Client(), sendMessageDirect(MSG(wire::KexInitMsg, _)));
  EXPECT_CALL(this->Client(), sendMessageDirect(MSG(wire::DisconnectMsg, _)));

  // If the disconnect message were queued, the server would instead receive the KexInitMsg first.
  // Note that onKexInitMsgSent occurs before the client actually sends the KexInitMsg.
  EXPECT_CALL(this->Server(), onMessageDecoded(MSG(wire::DisconnectMsg, _)))
    .WillOnce(InvokeWithoutArgs([this] {
      this->Client().Exit();
      this->Server().Exit();
      return absl::OkStatus();
    }));

  this->Client().Post([](auto& self) {
    EXPECT_OK(self.InitiateRekey());
  });

  this->Join();
}

TYPED_TEST(TransportBaseTest, TestSimultaneousRekeyOnRWThresholds) {
  this->ClientConfig().mutable_rekey_threshold()->set_value(16384);
  this->ServerConfig().mutable_rekey_threshold()->set_value(16384);

  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  // send a bunch of messages
  absl::Notification lastMessage;
  this->Client().Post([&lastMessage](auto& client) {
    ASSERT_EQ(16384, client.write_bytes_remaining_);
    while (client.write_bytes_remaining_ > 1044) { // number of bytes encrypted, less than 1060
      wire::IgnoreMsg msg;
      msg.data->resize(1024);
      auto n = client.sendMessageToConnection(std::move(msg));
      ASSERT_OK(n.status());
      EXPECT_EQ(1060, *n);
    }
    // the next message will trigger a rekey
    lastMessage.Notify();
  });
  lastMessage.WaitForNotificationWithTimeout(defaultTimeout());
  ASSERT_GT(this->Client().write_bytes_remaining_, 0);
  ASSERT_GT(this->Server().read_bytes_remaining_, 0);

  auto* const old_cipher = std::to_address(this->Client().cipher_);

  this->Client().Post([](auto& client) {
    EXPECT_CALL(client, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(client, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));  // (1) triggers re-kex by write threshold
    EXPECT_CALL(client, onKexInitMsgSent());                          // (2) client starts kex init
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (3)
    EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (9) client receives the server's kex init
    EXPECT_CALL(client, onKexStarted(false));                         // (10)
  });

  this->Server().Post([](auto& server) {
    EXPECT_CALL(server, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(server, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, _)));   // (4) triggers re-kex by read threshold
    EXPECT_CALL(server, onKexInitMsgSent());                          // (5) server also starts kex init
    EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (6)
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (7) server receives the client's kex init
    EXPECT_CALL(server, onKexStarted(false));                         // (8)
  });

  EXPECT_CALL(this->Client(), onKexCompleted(_, false))
    .WillOnce(Invoke([&](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      // this resets the cipher ^
      auto* const new_cipher = std::to_address(this->Client().cipher_);
      EXPECT_NE(old_cipher, new_cipher);
      EXPECT_EQ(16384, this->Client().write_bytes_remaining_);
      this->Client().Exit();
      this->Server().Exit();
    }));
  this->Client().Post([this](auto& client) {
    wire::IgnoreMsg msg;
    // write a message that will trigger the client's write threshold and the server's read threshold
    // at the same time
    msg.data->resize(std::max(this->Client().write_bytes_remaining_,
                              this->Server().read_bytes_remaining_));
    ASSERT_OK(client.sendMessageToConnection(std::move(msg)).status());
  });

  this->Join();
}

TYPED_TEST(TransportBaseTest, TestRekeyOnReadThreshold) {
  // Only set server rekey threshold; client's remains the default. The client will be sending lots
  // of messages to the server, but the server won't send messages back.
  this->ServerConfig().mutable_rekey_threshold()->set_value(16384);

  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  absl::Notification lastMessage;
  // first 15 messages are dropped
  testing::Sequence seq;
  EXPECT_CALL(this->Server(), onMessageDecoded(MSG(wire::IgnoreMsg, _)))
    .Times(14)
    .InSequence(seq);
  EXPECT_CALL(this->Server(), onMessageDecoded(MSG(wire::IgnoreMsg, _)))
    .InSequence(seq)
    .WillOnce(InvokeWithoutArgs([this, &lastMessage] {
      // 15th message
      // read_bytes_remaining_ is decremented after this to be under the threshold
      EXPECT_EQ(1808, this->Server().read_bytes_remaining_);
      lastMessage.Notify();
      return absl::OkStatus();
    }));

  for (int i = 0; i < 15; i++) {
    this->Client().Post([](auto& client) {
      wire::IgnoreMsg msg;
      msg.data->resize(1024);
      ASSERT_OK(client.sendMessageToConnection(std::move(msg)).status());
    });
  }
  lastMessage.WaitForNotificationWithTimeout(defaultTimeout());

  this->VerifyAndClearExpectations();

  this->Client().Post([](auto& client) {
    EXPECT_CALL(client, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(client, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));  // (1) client sends 16th msg
    EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (5) client receives the server's kex init
    EXPECT_CALL(client, onKexStarted(false));                         // (6)
    EXPECT_CALL(client, onKexInitMsgSent());                          // (7) client starts kex init
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (8)
  });

  this->Server().Post([](auto& server) {
    EXPECT_CALL(server, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(server, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, _)));   // (2) triggers re-kex by read threshold
    EXPECT_CALL(server, onKexInitMsgSent());                          // (3) server starts kex init
    EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (4)
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (9) server receives the client's kex init
    EXPECT_CALL(server, onKexStarted(false));                         // (10)
  });

  EXPECT_CALL(this->Server(), onKexCompleted(_, false))
    .WillOnce(Invoke([&](std::shared_ptr<KexResult> result, bool initial) {
      this->Server().TransportBase::onKexCompleted(result, initial);
      EXPECT_EQ(16384, this->Server().read_bytes_remaining_);
      this->Client().Exit();
      this->Server().Exit();
    }));
  this->Client().Post([](auto& client) {
    wire::IgnoreMsg msg;
    msg.data->resize(1024);
    ASSERT_OK(client.sendMessageToConnection(std::move(msg)).status());
  });

  this->Join();
}

TYPED_TEST(TransportBaseTest, TestRekeyOnWriteThreshold) {
  // Only set client rekey threshold; server's remains the default.
  this->ClientConfig().mutable_rekey_threshold()->set_value(16384);

  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  absl::Notification lastMessage;
  testing::Sequence seq;
  EXPECT_CALL(this->Client(), sendMessageToConnection(MSG(wire::IgnoreMsg, _)))
    .Times(14)
    .InSequence(seq);
  EXPECT_CALL(this->Client(), sendMessageToConnection(MSG(wire::IgnoreMsg, _)))
    .InSequence(seq)
    .WillOnce(Invoke([this, &lastMessage](wire::Message&& msg) {
      // 15th message
      auto n = this->Client().TransportBase::sendMessageToConnection(std::move(msg));
      EXPECT_OK(n.status());
      EXPECT_EQ(724, this->Client().write_bytes_remaining_);
      lastMessage.Notify();
      return n;
    }));

  for (int i = 0; i < 15; i++) {
    this->Client().Post([](auto& client) {
      wire::IgnoreMsg msg;
      msg.data->resize(1024);
      ASSERT_OK(client.sendMessageToConnection(std::move(msg)).status());
    });
  }
  lastMessage.WaitForNotificationWithTimeout(defaultTimeout());

  this->VerifyAndClearExpectations();

  this->Client().Post([](auto& client) {
    EXPECT_CALL(client, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(client, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));  // (1) triggers re-kex by write threshold
    EXPECT_CALL(client, onKexInitMsgSent());                          // (2) client starts kex init
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (3) client sends kex init
    EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (9) client receives the server's kex init
    EXPECT_CALL(client, onKexStarted(false));                         // (10)
  });

  this->Server().Post([](auto& server) {
    EXPECT_CALL(server, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(server, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, _)));   // (4)
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (5) server receives the client's kex init
    EXPECT_CALL(server, onKexStarted(false));                         // (6)
    EXPECT_CALL(server, onKexInitMsgSent());                          // (7) server starts kex init
    EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (8)
  });

  EXPECT_CALL(this->Client(), onKexCompleted(_, false))
    .WillOnce(Invoke([&](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      EXPECT_EQ(16384, this->Client().write_bytes_remaining_);
      this->Client().Exit();
      this->Server().Exit();
    }));
  this->Client().Post([](auto& client) {
    wire::IgnoreMsg msg;
    msg.data->resize(1024);
    ASSERT_OK(client.sendMessageToConnection(std::move(msg)).status());
  });

  this->Join();
}

TYPED_TEST(TransportBaseTest, TestSimultaneousRekeyOnSeqNumThreshold) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  // Instead of sending 2 billion messages, cheat a bit.
  // We hard-code the sequence number limit for both client and server, so in this test both sides
  // will always trigger the re-key at the same time
  this->Client().Post([](auto& client) {
    client.seq_write_ = SeqnumRekeyLimit;
  });
  this->Server().Post([](auto& server) {
    server.seq_read_ = SeqnumRekeyLimit;
  });

  this->Client().Post([](auto& client) {
    EXPECT_CALL(client, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(client, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));  // (1) triggers re-kex by write seqnum threshold
    EXPECT_CALL(client, onKexInitMsgSent());                          // (2) client starts kex init
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (3)
    EXPECT_CALL(client, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (9) client receives the server's kex init
    EXPECT_CALL(client, onKexStarted(false));                         // (10)
  });

  this->Server().Post([](auto& server) {
    EXPECT_CALL(server, sendMessageDirect(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                                Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(server, onMessageDecoded(AllOf(Not(MSG(wire::IgnoreMsg, _)),
                                               Not(MSG(wire::KexInitMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, _)));   // (4) triggers re-kex by read seqnum threshold
    EXPECT_CALL(server, onKexInitMsgSent());                          // (5) server also starts kex init
    EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexInitMsg, _))); // (6)
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::KexInitMsg, _)));  // (7) server receives the client's kex init
    EXPECT_CALL(server, onKexStarted(false));                         // (8)
  });

  EXPECT_CALL(this->Client(), onKexCompleted(_, false))
    .WillOnce(Invoke([&](std::shared_ptr<KexResult> result, bool initial) {
      this->Client().TransportBase::onKexCompleted(result, initial);
      this->Client().Exit();
    }));
  EXPECT_CALL(this->Server(), onKexCompleted(_, false))
    .WillOnce(Invoke([&](std::shared_ptr<KexResult> result, bool initial) {
      this->Server().TransportBase::onKexCompleted(result, initial);
      this->Server().Exit();
    }));
  this->Client().Post([](auto& client) {
    ASSERT_OK(client.sendMessageToConnection(wire::Message{wire::IgnoreMsg{}}).status());
  });

  this->Join();
  EXPECT_EQ(this->Server().seq_read_, 0);
  EXPECT_EQ(this->Server().seq_write_, 0);
  EXPECT_EQ(this->Client().seq_read_, 0);
  EXPECT_EQ(this->Client().seq_write_, 0);
}

TYPED_TEST(TransportBaseTest, TestInitiateKexFailedOnWriteRekey) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  this->Client().Post([](auto& client) {
    client.seq_write_ = SeqnumRekeyLimit;
  });
  this->Server().Post([](auto& server) {
    server.seq_read_ = SeqnumRekeyLimit;
  });

  this->Client().Post([](auto& client) {
    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _)))
      .WillOnce(InvokeWithoutArgs([] {
        return absl::InternalError("test error");
      }));
  });

  this->Client().Post([this](auto& client) {
    ASSERT_EQ(absl::InternalError("failed to initiate rekey: test error"),
              client.sendMessageToConnection(wire::Message{wire::IgnoreMsg{}}).status());
    // the failure here happens synchronously; server never receives the message
    this->Client().Exit();
    this->Server().Exit();
  });

  this->Join();
}

TYPED_TEST(TransportBaseTest, TestInitiateKexFailedOnReadRekey) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  this->Client().Post([](auto& client) {
    client.seq_write_ = SeqnumRekeyLimit;
  });
  this->Server().Post([](auto& server) {
    server.seq_read_ = SeqnumRekeyLimit;
  });

  this->Client().Post([](auto& client) {
    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::KexInitMsg, _)));
  });

  this->Server().Post([](auto& server) {
    EXPECT_CALL(server, sendMessageDirect(MSG(wire::KexInitMsg, _)))
      .WillOnce(InvokeWithoutArgs([] {
        return absl::InternalError("test error");
      }));
  });

  EXPECT_CALL(this->ServerCallbacks(), onDecodingFailure("failed to initiate rekey: test error"))
    .WillOnce(InvokeWithoutArgs([this] {
      this->Server().Exit();
      this->Client().Exit();
    }));

  this->Client().Post([](auto& client) {
    ASSERT_OK(client.sendMessageToConnection(wire::Message{wire::IgnoreMsg{}}).status());
  });

  this->Join();
}

TYPED_TEST(TransportBaseTest, TestErrorSendingQueuedMessagesAfterRekey) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }
  this->Client().Post([](auto& client) {
    client.seq_write_ = SeqnumRekeyLimit;
  });
  this->Server().Post([](auto& server) {
    server.seq_read_ = SeqnumRekeyLimit;
  });

  this->Client().Post([](auto& client) {
    EXPECT_CALL(client, onMessageDecoded(AllOf(
                          Not(MSG(wire::DebugMsg, _)),
                          Not(MSG(wire::IgnoreMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(client, sendMessageDirect(AllOf(
                          Not(MSG(wire::DebugMsg, _)),
                          Not(MSG(wire::IgnoreMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, _)));

    EXPECT_CALL(client, onKexInitMsgSent())
      .WillOnce(InvokeWithoutArgs([&client] {
        client.TransportBase::onKexInitMsgSent();
        ASSERT_OK(client.sendMessageToConnection(wire::DebugMsg{.message = "client->server queued message"s}).status());
      }));
    EXPECT_CALL(client, sendMessageDirect(Not(MSG(wire::DebugMsg, _))))
      .Times(AnyNumber());
    EXPECT_CALL(client, sendMessageDirect(MSG(wire::DebugMsg, _)))
      .WillOnce(InvokeWithoutArgs([] {
        return absl::InternalError("test error");
      }));
  });

  this->Server().Post([](auto& server) {
    EXPECT_CALL(server, onMessageDecoded(AllOf(
                          Not(MSG(wire::DebugMsg, _)),
                          Not(MSG(wire::IgnoreMsg, _)))))
      .Times(AnyNumber());
    EXPECT_CALL(server, sendMessageDirect(AllOf(
                          Not(MSG(wire::DebugMsg, _)),
                          Not(MSG(wire::IgnoreMsg, _)))))
      .Times(AnyNumber());

    IN_SEQUENCE;
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, _)));

    EXPECT_CALL(server, onKexInitMsgSent())
      .WillOnce(InvokeWithoutArgs([&server] {
        server.TransportBase::onKexInitMsgSent();
        ASSERT_OK(server.sendMessageToConnection(wire::DebugMsg{.message = "server->client queued message"s}).status());
      }));

    EXPECT_CALL(server, sendMessageDirect(MSG(wire::DebugMsg, _)))
      .WillOnce(InvokeWithoutArgs([] {
        return absl::InternalError("test error");
      }));
  });

  EXPECT_CALL(this->ClientCallbacks(), onDecodingFailure("test error"))
    .WillOnce(InvokeWithoutArgs([this] {
      this->Client().Exit();
    }));
  EXPECT_CALL(this->ServerCallbacks(), onDecodingFailure("test error"))
    .WillOnce(InvokeWithoutArgs([this] {
      this->Server().Exit();
    }));

  this->Client().Post([](auto& client) {
    ASSERT_OK(client.sendMessageToConnection(wire::Message{wire::IgnoreMsg{}}).status());
  });
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestRekeyTriggeredDuringQueueReplay) {
  // This tests the following scenario: a key re-exchange is triggered, and several messages are
  // subsequently placed in the queue. Once the key exchange is completed, the transport begins
  // replaying the queued messages. While doing so, it exhausts the rekey limit and must pause
  // to begin another key exchange. Once _that_ key exchange is done, it may continue where it
  // left off replaying the queued messages.

  // One way to test this is by setting the rekey limit very low.
  this->ClientConfig().mutable_rekey_threshold()->set_value(256); // this is the minimum

  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  absl::Notification allQueuedMsgsSent;
  this->Server().Post([this, &allQueuedMsgsSent](auto& server) {
    EXPECT_CALL(server, onMessageDecoded(Not(MSG(wire::IgnoreMsg, _))))
      .Times(AnyNumber());

    testing::Sequence seq;
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, FIELD_EQ(data, bytes(256, 0)))))
      .InSequence(seq)
      .WillOnce(InvokeWithoutArgs([&allQueuedMsgsSent] {
        // delay the first re-exchange until all 100 messages have been enqueued
        // (this makes it easier to configure the expected call sequence)
        allQueuedMsgsSent.WaitForNotification();
        return absl::OkStatus();
      }));
    for (uint8_t i = 1; i < 99; i++) {
      EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, FIELD_EQ(data, bytes(256, i)))))
        .InSequence(seq);
    }
    EXPECT_CALL(server, onMessageDecoded(MSG(wire::IgnoreMsg, FIELD_EQ(data, bytes(256, 99)))))
      .InSequence(seq)
      .WillOnce(InvokeWithoutArgs([this] {
        this->Client().Exit();
        this->Server().Exit();
        return absl::OkStatus();
      }));
  });
  this->Client().Post([](auto& client) {
    testing::Sequence seq;
    EXPECT_CALL(client, sendMessageDirect(Not(MSG(wire::IgnoreMsg, _))))
      .Times(AnyNumber());
    for (uint8_t i = 0; i < 100; i++) {
      EXPECT_CALL(client, sendMessageDirect(MSG(wire::IgnoreMsg, FIELD_EQ(data, bytes(256, i)))))
        .InSequence(seq);
      if (i != 99) {
        EXPECT_CALL(client, onKexStarted(false))
          .InSequence(seq);
        EXPECT_CALL(client, onKexCompleted(_, false))
          .InSequence(seq);
      }
    }
  });
  this->Client().Post([&allQueuedMsgsSent](auto& client) {
    for (uint8_t i = 0; i < 100; i++) {
      ASSERT_OK(client.sendMessageToConnection(wire::Message{wire::IgnoreMsg{.data = bytes(256, i)}}).status());
    }
    allQueuedMsgsSent.Notify();
  });
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestErrorEncodingPacket) {
  this->Start();
  this->Client().Post([this](auto& client) {
    wire::Message msg{wire::IgnoreMsg{.data = bytes(wire::MaxPacketSize + 1, 0)}};
    EXPECT_EQ(absl::AbortedError("error encoding packet: message size too large"),
              client.sendMessageDirect(std::move(msg)).status());
    this->Client().Exit();
    this->Server().Exit();
  });
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestUnimplementedMsg) {
  if (!this->StartAndWaitForInitialKeyExchange()) {
    return;
  }

  EXPECT_CALL(this->Server(), onMessageDecoded(Truly([](const wire::Message& msg) {
                return !msg.has_value();
              })));
  EXPECT_CALL(this->Client(), onMessageDecoded(MSG(wire::UnimplementedMsg, _)))
    .WillOnce(Invoke([this](wire::Message&& msg) {
      auto expected_seqnum = this->Client().seq_write_ - 1;
      auto actual_seqnum = msg.message.get<wire::UnimplementedMsg>().sequence_number;
      EXPECT_EQ(expected_seqnum, actual_seqnum);
      this->Client().Exit();
      this->Server().Exit();
      return absl::OkStatus();
    }));

  this->Client().Post([](auto& client) {
    Buffer::OwnedImpl buffer;
    wire::write(buffer, wire::SshMessageType(200));
    wire::Message msg;
    EXPECT_OK(msg.decode(buffer, buffer.length()).status());
    ASSERT_OK(client.sendMessageToConnection(std::move(msg)).status());
  });

  this->Join();
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec