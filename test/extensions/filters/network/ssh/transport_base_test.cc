#include "source/extensions/filters/network/ssh/transport_base.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/test_common/test_common.h"
#include "test/test_common/utility.h"

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

  MOCK_METHOD(void, updatePeerExtInfo, (std::optional<wire::ExtInfoMsg>), (override));                   // delegates to the base class
  MOCK_METHOD(void, onKexStarted, (bool), (override));                                                   // delegates to the base class
  MOCK_METHOD(void, onKexCompleted, (std::shared_ptr<KexResult>, bool), (override));                     // delegates to the base class
  MOCK_METHOD(void, onVersionExchangeCompleted, (const bytes&, const bytes&, const bytes&), (override)); // delegates to the base class
  MOCK_METHOD(absl::Status, onMessageDecoded, (wire::Message&&), (override));                            // delegates to the base class

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
          dispatcher_->exit();
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

  void Exit() {
    RELEASE_ASSERT(dispatcher_->isThreadSafe(), "test bug: not thread-safe");
    dispatcher_->exit();
  }

  void Post(::Envoy::Event::PostCb fn) {
    dispatcher_->post(std::move(fn));
  }

  void SetVersion(std::string_view version) {
    this->server_version_ = version;
  }

private:
  ::Envoy::Event::DispatcherPtr dispatcher_;
};

template <typename TestOptions>
class TransportBaseTest : public testing::Test {
public:
  TransportBaseTest()
      : api_(Api::createApiForTest()),
        server_transport_(*api_, [] {
          auto cfg = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
          for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
            cfg->add_host_keys(copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600));
          }
          return cfg;
        }()),
        client_transport_(*api_, [] {
          auto cfg = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
          for (auto keyName : {"rsa_2", "ecdsa_2", "ed25519_2"}) {
            cfg->add_host_keys(copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600));
          }
          return cfg;
        }()) {}

  void SetUp() override {
    // wire up the transports to send data to each other; each transport runs its own dispatcher on
    // a separate thread.
    EXPECT_CALL(server_codec_callbacks_, writeToConnection)
      .WillRepeatedly(Invoke([&](Envoy::Buffer::Instance& input) {
        Buffer::OwnedImpl buffer;
        buffer.move(input);
        client_transport_.Post([this, buffer = std::move(buffer)] mutable {
          client_transport_.decode(buffer, false);
        });
      }));
    EXPECT_CALL(client_codec_callbacks_, writeToConnection)
      .WillRepeatedly(Invoke([&](Envoy::Buffer::Instance& input) {
        Buffer::OwnedImpl buffer;
        buffer.move(input);
        server_transport_.Post([this, buffer = std::move(buffer)] mutable {
          server_transport_.decode(buffer, false);
        });
      }));
    server_transport_.setCodecCallbacks(server_codec_callbacks_);
    client_transport_.setCodecCallbacks(client_codec_callbacks_);
  }

  void Start(absl::Duration timeout = absl::Seconds(1)) {
    if (isDebuggerAttached()) {
      timeout = absl::Hours(1);
    }
    server_thread_ = server_transport_.StartThread(timeout);
    client_thread_ = client_transport_.StartThread(timeout);
  }

  void Join() {
    server_thread_->join();
    client_thread_->join();
  }

  auto& InitiatingTransport() {
    if constexpr (TestOptions::client_initiates) {
      return client_transport_;
    } else {
      return server_transport_;
    }
  }

  auto& NonInitiatingTransport() {
    if constexpr (TestOptions::client_initiates) {
      return server_transport_;
    } else {
      return client_transport_;
    }
  }

  auto& InitiatingCallbacks() {
    if constexpr (TestOptions::client_initiates) {
      return client_codec_callbacks_;
    } else {
      return server_codec_callbacks_;
    }
  }

  auto& NonInitiatingCallbacks() {
    if constexpr (TestOptions::client_initiates) {
      return server_codec_callbacks_;
    } else {
      return client_codec_callbacks_;
    }
  }

  void InitiateVersionExchange() {
    // The constraint that the client initiates the handshake doesn't apply at this abstraction level
    InitiatingTransport().Post([this] {
      InitiatingTransport().InitiateVersionExchange();
    });
  }

protected:
  Api::ApiPtr api_;
  Thread::ThreadPtr server_thread_;
  Thread::ThreadPtr client_thread_;
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
  EXPECT_CALL(this->InitiatingTransport(), onKexStarted(true));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexStarted(true));

  KexResultSharedPtr clientKexResult;
  KexResultSharedPtr serverKexResult;
  EXPECT_CALL(this->InitiatingTransport(), onKexCompleted(_, true))
    .WillOnce(DoAll(SaveArg<0>(&clientKexResult),
                    Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
                      this->InitiatingTransport().TransportBase::onKexCompleted(result, initial);
                      this->InitiatingTransport().Exit();
                    })));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexCompleted(_, true))
    .WillOnce(DoAll(SaveArg<0>(&serverKexResult),
                    Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
                      this->NonInitiatingTransport().TransportBase::onKexCompleted(result, initial);
                      this->NonInitiatingTransport().Exit();
                    })));

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
  EXPECT_EQ(*clientKexResult, *serverKexResult);
  EXPECT_EQ(this->InitiatingTransport().sessionId(), clientKexResult->session_id);
  EXPECT_EQ(this->NonInitiatingTransport().sessionId(), serverKexResult->session_id);
}

TYPED_TEST(TransportBaseTest, TestHandshakeWithExtInfo) {
  wire::ExtInfoMsg info;
  info.extensions->emplace_back(wire::PingExtension{.version = "0"s});
  this->InitiatingTransport().SetOutgoingExtInfo(auto(info));
  this->NonInitiatingTransport().SetOutgoingExtInfo(auto(info));

  EXPECT_CALL(this->InitiatingTransport(), onKexStarted(true));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexStarted(true));

  EXPECT_CALL(this->InitiatingTransport(), updatePeerExtInfo(_))
    .WillOnce(Invoke([this](std::optional<wire::ExtInfoMsg> msg) {
      this->InitiatingTransport().TransportBase::updatePeerExtInfo(std::move(msg));
      this->InitiatingTransport().Exit();
    }));
  EXPECT_CALL(this->NonInitiatingTransport(), updatePeerExtInfo(_))
    .WillOnce(Invoke([this](std::optional<wire::ExtInfoMsg> msg) {
      this->NonInitiatingTransport().TransportBase::updatePeerExtInfo(std::move(msg));
      this->NonInitiatingTransport().Exit();
    }));
  EXPECT_CALL(this->InitiatingTransport(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->InitiatingTransport().TransportBase::onKexCompleted(result, initial);
      EXPECT_OK(this->InitiatingTransport().sendMessageToConnection(*this->InitiatingTransport().outgoingExtInfo()).status());
    }));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->NonInitiatingTransport().TransportBase::onKexCompleted(result, initial);
      EXPECT_OK(this->NonInitiatingTransport().sendMessageToConnection(*this->NonInitiatingTransport().outgoingExtInfo()).status());
    }));

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
  EXPECT_EQ(info, this->InitiatingTransport().peerExtInfo());
  EXPECT_EQ(info, this->NonInitiatingTransport().peerExtInfo());
  EXPECT_EQ(std::nullopt, this->InitiatingTransport().outgoingExtInfo());
  EXPECT_EQ(std::nullopt, this->NonInitiatingTransport().outgoingExtInfo());
}

TYPED_TEST(TransportBaseTest, TestVersionExchange_InvalidVersion) {
  EXPECT_CALL(this->NonInitiatingCallbacks(), onDecodingFailure("version string contains invalid characters"sv))
    .WillOnce([this](std::string_view) {
      this->InitiatingTransport().Post([this] {
        this->InitiatingTransport().Exit();
      });
      this->NonInitiatingTransport().Exit();
    });
  this->InitiatingTransport().SetVersion("SSH-2.0--");

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestVersionExchangeIncomplete) {
  EXPECT_CALL(this->InitiatingCallbacks(), writeToConnection)
    .WillOnce(Invoke([&](Envoy::Buffer::Instance& input) {
      // send two buffers,
      Buffer::OwnedImpl buffer1; // "SSH-2.0-"
      buffer1.add(input.linearize(input.length()), input.length() / 2);
      Buffer::OwnedImpl buffer2; // "SSH-2.0-aaaaaa\r\n"
      buffer2.move(input);
      this->NonInitiatingTransport().Post([this, buffer = std::move(buffer1)] mutable {
        this->NonInitiatingTransport().decode(buffer, false);
      });
      this->NonInitiatingTransport().Post([this, buffer = std::move(buffer2)] mutable {
        this->NonInitiatingTransport().decode(buffer, false);
      });
    }));
  EXPECT_CALL(this->InitiatingTransport(), onVersionExchangeCompleted)
    .WillOnce(InvokeWithoutArgs([this] {
      this->InitiatingTransport().Exit();
    }));
  EXPECT_CALL(this->NonInitiatingTransport(), onVersionExchangeCompleted)
    .WillOnce(InvokeWithoutArgs([this] {
      this->NonInitiatingTransport().Exit();
    }));
  this->InitiatingTransport().SetVersion("SSH-2.0-aaaaaa");

  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestDecryptPacketFailure) {
  EXPECT_CALL(this->InitiatingTransport(), onKexStarted(true));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexStarted(true));
  EXPECT_CALL(this->InitiatingTransport(), onKexCompleted(_, true));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexCompleted(_, true))
    .WillOnce(Invoke([this](std::shared_ptr<KexResult> result, bool initial) {
      this->NonInitiatingTransport().TransportBase::onKexCompleted(result, initial);
      this->InitiatingTransport().Post([this] {
        // change the receiver's sequence number, so they will fail to decrypt the packet
        this->InitiatingTransport().seq_read_++;
        // then send them a message
        this->NonInitiatingTransport().Post([this] {
          EXPECT_OK(this->NonInitiatingTransport().sendMessageToConnection(wire::Message{wire::DebugMsg{}}).status());
          this->NonInitiatingTransport().Exit();
        });
      });
    }));

  EXPECT_CALL(this->InitiatingCallbacks(), onDecodingFailure(HasSubstr("failed to decrypt packet"s)))
    .WillOnce(InvokeWithoutArgs([this] {
      this->InitiatingTransport().Exit();
    }));
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestReadIncompletePacket) {
  EXPECT_CALL(this->InitiatingTransport(), onKexStarted(true));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexStarted(true));
  EXPECT_CALL(this->NonInitiatingTransport(), onKexCompleted(_, true));

  wire::Message expectedMsg{wire::IgnoreMsg{.data = "foo"_bytes}};
  EXPECT_CALL(this->InitiatingTransport(), onKexCompleted(_, true))
    .WillOnce(Invoke([this, expectedMsg](std::shared_ptr<KexResult> result, bool initial) {
      this->InitiatingTransport().TransportBase::onKexCompleted(result, initial);
      IN_SEQUENCE;
      EXPECT_CALL(this->InitiatingCallbacks(), writeToConnection)
        .WillOnce(Invoke([&](Envoy::Buffer::Instance& input) {
          Buffer::OwnedImpl buffer1;
          buffer1.add(input.linearize(input.length()), input.length() / 2);
          Buffer::OwnedImpl buffer2;
          buffer2.move(input);
          this->NonInitiatingTransport().Post([this, buffer = std::move(buffer1)] mutable {
            this->NonInitiatingTransport().decode(buffer, false);
          });
          this->NonInitiatingTransport().Post([this, buffer = std::move(buffer2)] mutable {
            this->NonInitiatingTransport().decode(buffer, false);
          });
        }));
      EXPECT_CALL(this->NonInitiatingTransport(), onMessageDecoded(MSG(wire::IgnoreMsg, Eq(wire::IgnoreMsg{.data = "foo"_bytes}))))
        .WillOnce(Invoke([this](wire::Message&&) {
          this->NonInitiatingTransport().Exit();
          this->InitiatingTransport().Post([this] {
            this->InitiatingTransport().Exit();
          });
          return absl::OkStatus();
        }));
      EXPECT_OK(this->InitiatingTransport().sendMessageToConnection(auto(expectedMsg)).status());
    }));
  this->Start();
  this->InitiateVersionExchange();
  this->Join();
}

TYPED_TEST(TransportBaseTest, TestDecodePacketFailure) {
}

TYPED_TEST(TransportBaseTest, TestDecodeMessageFailure) {
}

TYPED_TEST(TransportBaseTest, TestRekeyManual) {
}

TYPED_TEST(TransportBaseTest, TestRekeyWithQueuedMessages) {
}

TYPED_TEST(TransportBaseTest, TestRekeyOnWriteThreshold) {
}

TYPED_TEST(TransportBaseTest, TestRekeyOnReadThreshold) {
}

TYPED_TEST(TransportBaseTest, TestInitiateKexFailed) {
}

TYPED_TEST(TransportBaseTest, TestRunInNextIteration) {
}

TYPED_TEST(TransportBaseTest, TestErrorEncodingPacket) {
}

TYPED_TEST(TransportBaseTest, TestErrorEncryptingPacket) {
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec