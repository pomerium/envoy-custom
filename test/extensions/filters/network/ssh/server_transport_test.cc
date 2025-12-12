#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/id_manager.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h" // IWYU pragma: keep
#include "test/extensions/filters/network/ssh/test_mocks.h"              // IWYU pragma: keep
#include "test/mocks/network/connection.h"
#include "test/mocks/grpc/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/proto_equal.h"
#include "test/test_common/test_common.h"
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep
#include "gmock/gmock.h"
#include "gtest/gtest.h"

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

using namespace pomerium::extensions::ssh;

// NOLINTBEGIN(readability-identifier-naming)
class ServerTransportTest : public testing::Test {
public:
  ServerTransportTest()
      : server_config_(newConfig()),
        client_host_key_(*openssh::SSHKey::generate(KEY_ED25519, 256)),
        secrets_provider_(*server_config_),
        transport_([this] {
          ON_CALL(server_factory_context_.drain_manager_, addOnDrainCloseCb)
            .WillByDefault([this](Network::DrainDirection, Network::DrainDecision::DrainCloseCb cb) {
              return drain_close_callbacks_.add(std::move(cb));
            });
          ON_CALL(server_factory_context_.drain_manager_, startDrainSequence)
            .WillByDefault([this](Network::DrainDirection, std::function<void()> completion) {
              ASSERT_OK(drain_close_callbacks_.runCallbacks(std::chrono::milliseconds{}));
              completion();
            });
          return SshServerTransport(
            server_factory_context_,
            server_config_,
            [this] {
              auto client = std::make_shared<testing::NiceMock<Grpc::MockAsyncClient>>();
              ON_CALL(*client, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
                .WillByDefault(Invoke([this](absl::string_view, absl::string_view,
                                             Envoy::Grpc::RawAsyncStreamCallbacks& callbacks,
                                             const Http::AsyncClient::StreamOptions&) {
                  // dynamic cast the reference, not the pointer, so that failures throw an exception instead
                  // of returning nullptr
                  ASSERT(manage_stream_callbacks_ == nullptr);
                  manage_stream_callbacks_ = &dynamic_cast<Envoy::Grpc::AsyncStreamCallbacks<ServerMessage>&>(callbacks);
                  return &manage_stream_stream_;
                }));
              ON_CALL(*client, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
                .WillByDefault(Invoke([this](absl::string_view, absl::string_view,
                                             Envoy::Grpc::RawAsyncStreamCallbacks& callbacks,
                                             const Http::AsyncClient::StreamOptions&) {
                  serve_channel_callbacks_.push_back(&dynamic_cast<Envoy::Grpc::AsyncStreamCallbacks<ChannelMessage>&>(callbacks));
                  return &serve_channel_stream_;
                }));

              return client;
            },
            StreamTracker::fromContext(server_factory_context_),
            secrets_provider_);
        }()) {}

  const wire::KexInitMsg kex_init_ = {
    .cookie = {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
    .kex_algorithms = {{"curve25519-sha256"s, "ext-info-c"s, "kex-strict-c-v00@openssh.com"s}},
    .server_host_key_algorithms = {{"ssh-ed25519"s}},
    .encryption_algorithms_client_to_server = {{"chacha20-poly1305@openssh.com"s}},
    .encryption_algorithms_server_to_client = {{"chacha20-poly1305@openssh.com"s}},
    .compression_algorithms_client_to_server = {{"none"s}},
    .compression_algorithms_server_to_client = {{"none"s}},
  };
  const Algorithms kex_algs_ = {
    .kex = "curve25519-sha256"s,
    .host_key = "ssh-ed25519"s,
    .client_to_server = {
      .cipher = "chacha20-poly1305@openssh.com"s,
      .compression = "none"s,
    },
    .server_to_client = {
      .cipher = "chacha20-poly1305@openssh.com"s,
      .compression = "none"s,
    },
  };

  void SetUp() {
    transport_.setCodecCallbacks(server_codec_callbacks_);
    ON_CALL(server_codec_callbacks_, writeToConnection(_))
      .WillByDefault([this](Envoy::Buffer::Instance& buffer) {
        output_buffer_.move(buffer);
      });
    EXPECT_CALL(server_codec_callbacks_, writeToConnection(_))
      .Times(AnyNumber());
    ON_CALL(server_codec_callbacks_, connection())
      .WillByDefault(Return(makeOptRef<Network::Connection>(mock_connection_)));
    EXPECT_CALL(server_codec_callbacks_, connection())
      .Times(AnyNumber());

    terminate_cb_ = new NiceMock<Envoy::Event::MockSchedulableCallback>(&mock_connection_.dispatcher_);
    EXPECT_CALL(*terminate_cb_, scheduleCallbackNextIteration)
      .Times(testing::AtMost(1))
      .WillOnce([&] {
        terminate_cb_->scheduleCallbackCurrentIteration();
        terminate_cb_->invokeCallback();
      });
    transport_.onConnected();
    // check that the connection dispatcher is set after onConnected()
    ASSERT_TRUE(transport_.connectionDispatcher().has_value());
    ASSERT_EQ(transport_.connectionDispatcher().ptr(), &mock_connection_.dispatcher_);
    // Replace the transport's ChannelIDManager to set the starting channel ID to 100. This makes
    // it easier to differentiate internal IDs in tests. The default starting ID is also 0, which
    // causes fields to be omitted when printing protobuf messages.
    // ChannelIDManager is not copyable or movable so we need to reconstruct it in-place. It is
    // normally created in the onConnected() callback above.
    ChannelIDManager* mgr = &transport_.channelIdManager();
    ASSERT(mgr->numActiveChannels() == 0);
    mgr->~ChannelIDManager();
    new (mgr) ChannelIDManager(100, 100);

    // Perform a manual key exchange as the client and set up a packet cipher
    input_buffer_.add("SSH-2.0-TestClient\r\n");
    transport_.decode(input_buffer_, false);
    EXPECT_TRUE(output_buffer_.startsWith("SSH-2.0-Envoy\r\n"));
    output_buffer_.drain(15);
    wire::KexInitMsg serverKexInit;
    ASSERT_OK(wire::decodePacket(output_buffer_, serverKexInit).status());
    ASSERT_OK(wire::encodePacket(input_buffer_, kex_init_, 8, 0).status());
    transport_.decode(input_buffer_, false);
    HandshakeMagics magics{
      .client_version = "SSH-2.0-TestClient"_bytes,
      .server_version = "SSH-2.0-Envoy"_bytes,
      .client_kex_init = *wire::encodeTo<bytes>(kex_init_),
      .server_kex_init = *wire::encodeTo<bytes>(serverKexInit),
    };
    // we can just pick an algorithm, not testing the packet cipher itself here

    DirectionalPacketCipherFactoryRegistry reg;
    reg.registerType<Chacha20Poly1305CipherFactory>();
    Curve25519Sha256KexAlgorithmFactory f;
    auto kexAlg = f.create(&magics, &kex_algs_, client_host_key_.get());
    auto ourEcdhInit = kexAlg->buildClientInit();
    ASSERT_OK(wire::encodePacket(input_buffer_, ourEcdhInit, 8, 0).status());
    transport_.decode(input_buffer_, false);

    wire::Message serverEcdhReply;
    ASSERT_OK(wire::decodePacket(output_buffer_, serverEcdhReply).status());
    auto r = kexAlg->handleClientRecv(serverEcdhReply);
    ASSERT_OK(r.status());
    ASSERT_TRUE(r->has_value());
    (**r)->session_id = (**r)->exchange_hash; // this needs to be set manually
    current_session_id_ = (**r)->session_id;

    client_cipher_ = makePacketCipherFromKexResult<ClientCodec>(reg, (*r)->get());
    ASSERT_NE(nullptr, client_cipher_);

    ASSERT_OK(wire::encodePacket(input_buffer_, wire::NewKeysMsg{}, 8, 0).status());
    transport_.decode(input_buffer_, false);
    wire::NewKeysMsg serverNewKeys;
    ASSERT_OK(wire::decodePacket(output_buffer_, serverNewKeys).status());
  }

  void SetAuthInfo(AuthInfoSharedPtr info) {
    ASSERT(!mock_connection_.streamInfo().filterState()->hasDataWithName(AuthInfoFilterStateKey));
    mock_connection_.streamInfo().filterState()->setData(
      AuthInfoFilterStateKey, info,
      StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Request,
      StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
  }

  absl::Status WriteMsg(wire::Message&& msg) {
    Buffer::OwnedImpl buf;
    if (auto n = wire::encodePacket(buf, msg,
                                    client_cipher_->blockSize(openssh::CipherMode::Write),
                                    client_cipher_->aadSize(openssh::CipherMode::Write));
        !n.ok()) {
      return n.status();
    }
    if (auto stat = client_cipher_->encryptPacket(write_seqnum_++, input_buffer_, buf); !stat.ok()) {
      return stat;
    }
    transport_.decode(input_buffer_, false);
    return absl::OkStatus();
  }

  absl::Status ReadMsg(auto& msg) {
    Buffer::OwnedImpl buf;
    if (auto n = client_cipher_->decryptPacket(read_seqnum_++, buf, output_buffer_); !n.ok()) {
      return n.status();
    }
    return wire::decodePacket(buf, msg).status();
  }

  absl::Status ReadExtInfo() {
    wire::ExtInfoMsg serverExtInfo;
    return ReadMsg(serverExtInfo);
  }

  absl::Status RequestUserAuthService() {
    wire::ServiceRequestMsg serviceReq{.service_name = "ssh-userauth"s};
    RETURN_IF_NOT_OK(WriteMsg(wire::Message{serviceReq}));
    wire::ServiceAcceptMsg serviceAccept;
    RETURN_IF_NOT_OK(ReadMsg(serviceAccept));
    EXPECT_EQ("ssh-userauth", serviceAccept.service_name);
    return serviceAccept.service_name == "ssh-userauth"
             ? absl::OkStatus()
             : absl::InternalError("test failure");
  }

  std::pair<wire::Message, ClientMessage> BuildUserAuthMessages(openssh::SSHKey& clientKey) {
    wire::UserAuthRequestMsg authReq;
    authReq.username = "test@example";
    authReq.service_name = "ssh-connection";
    wire::PubKeyUserAuthRequestMsg pubkeyReq{
      .has_signature = true,
      .public_key_alg = std::string(clientKey.keyTypeName()),
      .public_key = clientKey.toPublicKeyBlob(),
    };
    Envoy::Buffer::OwnedImpl sig;
    wire::write_opt<wire::LengthPrefixed>(sig, *current_session_id_);
    wire::field<std::string, wire::LengthPrefixed> methodName{"publickey"s};
    EXPECT_OK(wire::encodeMsg(sig, authReq.msg_type(),
                              authReq.username,
                              authReq.service_name,
                              methodName,
                              pubkeyReq.has_signature,
                              pubkeyReq.public_key_alg,
                              pubkeyReq.public_key)
                .status());
    pubkeyReq.signature = *clientKey.sign(linearizeToSpan(sig));

    AuthenticationRequest grpcAuthReq;
    grpcAuthReq.set_protocol("ssh");
    grpcAuthReq.set_service("ssh-connection");
    grpcAuthReq.set_auth_method("publickey");
    grpcAuthReq.set_hostname("example");
    grpcAuthReq.set_username("test");

    PublicKeyMethodRequest method_req;
    method_req.set_public_key(pubkeyReq.public_key->data(), pubkeyReq.public_key->size());
    method_req.set_public_key_alg(pubkeyReq.public_key_alg);
    auto clientKeyFp = clientKey.rawFingerprint();
    method_req.set_public_key_fingerprint_sha256(clientKeyFp.data(), clientKeyFp.size());
    grpcAuthReq.mutable_method_request()->PackFrom(method_req);

    ClientMessage clientMsg;
    *clientMsg.mutable_auth_request() = grpcAuthReq;
    authReq.request = std::move(pubkeyReq);
    return {wire::Message{std::move(authReq)}, std::move(clientMsg)};
  }

  void ExpectHandlePomeriumGrpcAuthRequestNormal(const ClientMessage& clientMsg) {
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(clientMsg), false))
      .WillOnce([this](Buffer::InstancePtr&, bool) {
        auto response = std::make_unique<ServerMessage>();
        auto* allow = response->mutable_auth_response()->mutable_allow();
        allow->set_username("test");
        auto* upstream = allow->mutable_upstream();
        upstream->set_hostname("example");
        *upstream->add_allowed_methods()->mutable_method() = "publickey";
        manage_stream_callbacks_->onReceiveMessage(std::move(response));
      });
  }

  void ExpectHandlePomeriumGrpcAuthRequestHijack(const ClientMessage& clientMsg, bool add_well_known_metadata = false) {
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(clientMsg), false))
      .WillOnce([this, add_well_known_metadata](Buffer::InstancePtr&, bool) {
        auto response = std::make_unique<ServerMessage>();
        auto* allow = response->mutable_auth_response()->mutable_allow();
        allow->set_username("test");
        auto* internal = allow->mutable_internal();
        (*internal->mutable_set_metadata()->mutable_filter_metadata())["foo"] = Protobuf::Struct{};
        if (add_well_known_metadata) {
          pomerium::extensions::ssh::FilterMetadata sshMetadata;
          sshMetadata.set_stream_id(999); // not otherwise set by us
          (*internal->mutable_set_metadata()->mutable_typed_filter_metadata())["com.pomerium.ssh"].PackFrom(sshMetadata);
        }
        manage_stream_callbacks_->onReceiveMessage(std::move(response));
      });
  }

  void ExpectUpstreamConnectEvent() {
    ClientMessage upstreamConnectMsg{};
    upstreamConnectMsg.mutable_event()->mutable_upstream_connected();
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(upstreamConnectMsg), false));
  }

  void ExpectDecodingSuccess(std::string host = "example") {
    EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_, _)) // header frame overload
      .WillOnce(Invoke([this, host](RequestHeaderFramePtr frame, absl::optional<StartTime>) {
        EXPECT_EQ(host, frame->host());
        EXPECT_EQ("ssh", frame->protocol());
        EXPECT_EQ(transport_.streamId(), frame->frameFlags().streamId());
        EXPECT_EQ(0, frame->frameFlags().rawFlags());
        EXPECT_EQ(FrameTags::RequestHeader | FrameTags::EffectiveHeader, frame->frameFlags().frameTags());
      }));
  }

  void ExpectSendOnServeChannelStream(const ChannelMessage& msg) {
    EXPECT_CALL(serve_channel_stream_, sendMessageRaw_(ProtoBufferStrictEq(msg), false));
  }

  void ExpectSendOnServeChannelStream(wire::Encoder auto const& msg) {
    ChannelMessage channelMsg;
    *channelMsg.mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(msg);
    EXPECT_CALL(serve_channel_stream_, sendMessageRaw_(ProtoBufferStrictEq(channelMsg), false));
  }

  void ExpectSendOnManagementStream(const ClientMessage& msg) {
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(msg), false));
  }

  // stream_index identifies the specific stream (in order of creation), if multiple streams are
  // created during a test.
  void ReceiveOnServeChannelStream(const ChannelMessage& msg, size_t stream_index = 0) {
    auto ptr = std::make_unique<ChannelMessage>(msg);
    serve_channel_callbacks_[stream_index]->onReceiveMessage(std::move(ptr));
  }

  testing::NiceMock<Server::Configuration::MockServerFactoryContext> server_factory_context_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> server_config_;
  Envoy::Common::CallbackManager<absl::Status, std::chrono::milliseconds> drain_close_callbacks_;

  seqnum_t read_seqnum_{};
  seqnum_t write_seqnum_{};
  std::optional<bytes> current_session_id_;
  std::unique_ptr<PacketCipher> client_cipher_;
  Envoy::Buffer::OwnedImpl input_buffer_;
  Envoy::Buffer::OwnedImpl output_buffer_;
  openssh::SSHKeyPtr client_host_key_;
  TestSecretsProvider secrets_provider_;
  testing::StrictMock<MockServerCodecCallbacks> server_codec_callbacks_;
  testing::NiceMock<Envoy::Network::MockServerConnection> mock_connection_;
  Envoy::Grpc::AsyncStreamCallbacks<ServerMessage>* manage_stream_callbacks_{};
  std::vector<Envoy::Grpc::AsyncStreamCallbacks<ChannelMessage>*> serve_channel_callbacks_;
  testing::NiceMock<Grpc::MockAsyncStream> manage_stream_stream_;
  testing::NiceMock<Grpc::MockAsyncStream> serve_channel_stream_;
  SshServerTransport transport_;
  NiceMock<Envoy::Event::MockSchedulableCallback>* terminate_cb_;

private:
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> newConfig() {
    auto conf = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
    for (auto keyName : {"rsa_1", "ed25519_1"}) {
      auto hostKeyFile = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
      conf->add_host_keys()->set_filename(hostKeyFile);
    }
    auto userCaKeyFile = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_2", 0600);
    conf->mutable_user_ca_key()->set_filename(userCaKeyFile);
    return conf;
  }
};
MATCHER_P(RequestCommonFrameWithMsg, msg, "") {
  const auto& actual = dynamic_cast<const SSHRequestCommonFrame&>(*arg).message();
  if (wire::Message{std::move(msg)} == actual) {
    return true;
  }
  *result_listener << actual;
  return false;
}
// NOLINTEND(readability-identifier-naming)

TEST_F(ServerTransportTest, Disconnect) {
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received disconnect: by application"sv));

  ASSERT_OK(WriteMsg(wire::DisconnectMsg{
    .reason_code = SSH2_DISCONNECT_BY_APPLICATION,
  }));
}

TEST_F(ServerTransportTest, Terminate) {
  ASSERT_OK(ReadExtInfo());

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("test error"sv));

  transport_.terminate(absl::ResourceExhaustedError("test error"));

  wire::DisconnectMsg disconnect;
  ASSERT_OK(ReadMsg(disconnect));
  EXPECT_EQ(disconnect.description, "Resource Exhausted: test error");
}

TEST_F(ServerTransportTest, TerminateTwice) {
  ASSERT_OK(ReadExtInfo());

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("test error"sv));

  transport_.terminate(absl::ResourceExhaustedError("test error"));
  transport_.terminate(absl::InternalError("ignored"));

  wire::DisconnectMsg disconnect;
  ASSERT_OK(ReadMsg(disconnect));
  EXPECT_EQ(disconnect.description, "Resource Exhausted: test error");
}

// Validate the server's initial ExtInfoMsg
TEST_F(ServerTransportTest, InitialExtInfo) {
  wire::ExtInfoMsg serverExtInfo;
  ASSERT_OK(ReadMsg(serverExtInfo));
  EXPECT_TRUE(serverExtInfo.hasExtension<wire::PingExtension>());
  EXPECT_TRUE(serverExtInfo.hasExtension<wire::ExtInfoInAuthExtension>());

  for (const auto& ext : *serverExtInfo.extensions) {
    ASSERT_TRUE(ext.extension.has_value());
    ext.extension.visit(
      [](const wire::PingExtension& ping) {
        ASSERT_EQ("0", ping.version);
      },
      [](const wire::ExtInfoInAuthExtension& ext) {
        ASSERT_EQ("0", ext.version);
      },
      [](const wire::ServerSigAlgsExtension& ext) {
        ASSERT_EQ((string_list{
                    "ssh-ed25519",
                    "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384",
                    "ecdsa-sha2-nistp521",
                    "rsa-sha2-512",
                    "rsa-sha2-256",
                  }),
                  ext.public_key_algorithms_accepted);
      },
      []<typename T>(const T&) {
        FAIL() << "unexpected extension: " << T::submsg_key << " (this test likely needs to be updated)";
      });
  }
}

TEST_F(ServerTransportTest, UnimplementedMessages) {
  ASSERT_OK(ReadExtInfo());

  Buffer::OwnedImpl buffer;
  wire::write(buffer, wire::SshMessageType(200));
  wire::Message msg;
  EXPECT_OK(msg.decode(buffer, buffer.length()).status());
  EXPECT_FALSE(msg.has_value()); // sanity check

  for (uint32_t i = 0; i < 10; i++) {
    ASSERT_OK(WriteMsg(auto(msg)));
    wire::UnimplementedMsg unimplemented;
    ASSERT_OK(ReadMsg(unimplemented));
    EXPECT_EQ(i, unimplemented.sequence_number);
  }
}

TEST_F(ServerTransportTest, HostKeysProve) {
  ASSERT_OK(ReadExtInfo());

  auto hostKeys = openssh::loadHostKeys(server_config_->host_keys());

  std::vector<bytes> hostKeyBlobs;
  for (const auto& hostKey : *hostKeys) {
    hostKeyBlobs.push_back(hostKey->toPublicKeyBlob());
  }

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .request = {wire::HostKeysProveRequestMsg{.hostkeys = hostKeyBlobs}},
  }));

  wire::GlobalRequestSuccessMsg response;
  ASSERT_OK(ReadMsg(response));
  ASSERT_OK(response.resolve<wire::HostKeysProveResponseMsg>());

  for (size_t i = 0; i < hostKeys->size(); i++) {
    Envoy::Buffer::OwnedImpl tmp;
    wire::write_opt<wire::LengthPrefixed>(tmp, "hostkeys-prove-00@openssh.com"s);
    wire::write_opt<wire::LengthPrefixed>(tmp, *current_session_id_);
    wire::write_opt<wire::LengthPrefixed>(tmp, hostKeyBlobs[i]);
    ASSERT_OK((*hostKeys)[i]->verify(response.response.get<wire::HostKeysProveResponseMsg>()
                                       .signatures[i],
                                     wire::flushTo<bytes>(tmp)));
  }
}

TEST_F(ServerTransportTest, HostKeysProve_InvalidRequest) {
  ASSERT_OK(ReadExtInfo());

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("error handling HostKeysProveRequest: invalid format"));
  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .request = {wire::HostKeysProveRequestMsg{.hostkeys = {{"not a public key blob"_bytes}}}},
  }));
  wire::DisconnectMsg disconnect;
  ASSERT_OK(ReadMsg(disconnect));
  EXPECT_EQ(disconnect.description, "Invalid Argument: error handling HostKeysProveRequest: invalid format");
}

TEST_F(ServerTransportTest, HostKeysProve_NotServerKey) {
  ASSERT_OK(ReadExtInfo());

  auto randomKey = *openssh::SSHKey::generate(KEY_ED25519, 256);
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("error handling HostKeysProveRequest: requested key is invalid"));
  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .request = {wire::HostKeysProveRequestMsg{
      .hostkeys = {{randomKey->toPublicKeyBlob()}},
    }},
  }));

  wire::DisconnectMsg disconnect;
  ASSERT_OK(ReadMsg(disconnect));
  EXPECT_EQ(disconnect.description, "Invalid Argument: error handling HostKeysProveRequest: requested key is invalid");
}

TEST_F(ServerTransportTest, HostKeysProve_NoKeyForAlgorithm) {
  ASSERT_OK(ReadExtInfo());

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("error handling HostKeysProveRequest: requested key is invalid"));
  auto dsaKey = *openssh::SSHKey::generate(KEY_ECDSA, 256);
  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .request = {wire::HostKeysProveRequestMsg{
      .hostkeys = {{dsaKey->toPublicKeyBlob()}},
    }},
  }));
  wire::DisconnectMsg disconnect;
  ASSERT_OK(ReadMsg(disconnect));
  EXPECT_EQ(disconnect.description, "Invalid Argument: error handling HostKeysProveRequest: requested key is invalid");
}

TEST_F(ServerTransportTest, TcpipForwardRequest_UpstreamNotReady) {
  ASSERT_OK(ReadExtInfo());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("unexpected message received: GlobalRequest (80)"))
    .Times(1);

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{},
  }));
}

TEST_F(ServerTransportTest, TcpipForwardCancel_UpstreamNotReady) {
  ASSERT_OK(ReadExtInfo());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("unexpected message received: GlobalRequest (80)"))
    .Times(1);

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::CancelTcpipForwardMsg{},
  }));
}

class ClientMessagesPreUserAuthTest : public ServerTransportTest, public testing::WithParamInterface<std::tuple<wire::Message, std::string_view>> {
public:
  void SetUp() override {
    ServerTransportTest::SetUp();
    wire::ExtInfoMsg serverExtInfo;
    ASSERT_OK(ReadMsg(serverExtInfo));
  }
};

TEST_P(ClientMessagesPreUserAuthTest, ClientMessagesPreUserAuth) {
  // the only messages the client should be allowed to send right now (immediately after kex)
  // are:
  // - ServiceRequest (ssh-userauth only)
  // - GlobalRequest (HostKeysProve only)
  // - Ignore
  // - Debug
  // - Unimplemented
  // - Disconnect
  // - Ping/Pong
  // - KexInit, to initiate a key re-exchange
  // - ExtInfo (the server always supports it)
  // Any other known message should result in an immediate disconnect. Unknown messages will be
  // dropped and replied to with an UnimplementedMsg, as per RFC4253 § 11.4.

  auto [msg, err] = GetParam();
  if (err != "") {
    EXPECT_CALL(server_codec_callbacks_, onDecodingFailure(_))
      .WillOnce([err](std::string_view actual) {
        EXPECT_EQ(err, actual);
      });
  }
  ASSERT_OK(WriteMsg(std::move(msg)));
  if (err != "") {
    // for KexInitMsg, the server sends its KexInit reply before checking the algorithms
    if (msg.msg_type() == wire::SshMessageType::KexInit) {
      wire::KexInitMsg serverKexInit;
      ASSERT_OK(ReadMsg(serverKexInit));
    }
    wire::DisconnectMsg serverDisconnect;
    ASSERT_OK(ReadMsg(serverDisconnect));
    EXPECT_THAT(*serverDisconnect.description, HasSubstr(err));
    EXPECT_EQ(2 /*SSH2_DISCONNECT_PROTOCOL_ERROR*/, *serverDisconnect.reason_code);
  }
}

INSTANTIATE_TEST_SUITE_P(ClientMessagesPreUserAuth, ClientMessagesPreUserAuthTest,
                         testing::ValuesIn(std::vector<std::tuple<wire::Message, std::string_view>>{
                           {wire::ServiceRequestMsg{.service_name = "ssh-userauth"s}, ""sv},
                           {wire::ServiceRequestMsg{.service_name = "ssh-connection"s}, "invalid service name"sv},
                           {wire::GlobalRequestMsg{.request = {wire::HostKeysProveRequestMsg{}}}, ""sv},
                           {wire::GlobalRequestMsg{}, "unexpected message received: GlobalRequest (80)"sv},
                           {wire::GlobalRequestMsg{.request = {wire::HostKeysMsg{}}}, "unexpected global request: hostkeys-00@openssh.com"sv},
                           {wire::GlobalRequestSuccessMsg{}, "unexpected message received: RequestSuccess (81)"sv},
                           {wire::GlobalRequestFailureMsg{}, "unexpected message received: RequestFailure (82)"sv},
                           {wire::IgnoreMsg{.data = "foo"_bytes}, ""sv},
                           {wire::DebugMsg{.message = "foo"s}, ""sv},
                           {wire::UnimplementedMsg{.sequence_number = 1234}, ""sv},
                           {wire::ExtInfoMsg{}, ""sv},
                           {wire::KexInitMsg{}, "no common algorithm for key exchange; client offered: []; server offered: [\"mlkem768x25519-sha256\", \"curve25519-sha256\", \"curve25519-sha256@libssh.org\"]"sv},

                           {wire::ServiceAcceptMsg{}, "unexpected message received: ServiceAccept (6)"sv},
                           {wire::NewKeysMsg{}, "unexpected message received: NewKeys (21)"sv},
                           {wire::UserAuthRequestMsg{}, "unexpected message received: UserAuthRequest (50)"sv},
                           {wire::UserAuthFailureMsg{}, "unexpected message received: UserAuthFailure (51)"sv},
                           {wire::UserAuthSuccessMsg{}, "unexpected message received: UserAuthSuccess (52)"sv},
                           {wire::UserAuthBannerMsg{}, "unexpected message received: UserAuthBanner (53)"sv},
                           {wire::ChannelOpenMsg{}, "unexpected message received: ChannelOpen (90)"sv},
                           {wire::ChannelOpenConfirmationMsg{}, "unexpected message received: ChannelOpenConfirmation (91)"sv},
                           {wire::ChannelOpenFailureMsg{}, "unexpected message received: ChannelOpenFailure (92)"sv},
                           {wire::ChannelWindowAdjustMsg{}, "unexpected message received: ChannelWindowAdjust (93)"sv},
                           {wire::ChannelDataMsg{}, "unexpected message received: ChannelData (94)"sv},
                           {wire::ChannelExtendedDataMsg{}, "unexpected message received: ChannelExtendedData (95)"sv},
                           {wire::ChannelEOFMsg{}, "unexpected message received: ChannelEOF (96)"sv},
                           {wire::ChannelCloseMsg{}, "unexpected message received: ChannelClose (97)"sv},
                           {wire::ChannelRequestMsg{}, "unexpected message received: ChannelRequest (98)"sv},
                           {wire::ChannelSuccessMsg{}, "unexpected message received: ChannelSuccess (99)"sv},
                           {wire::ChannelFailureMsg{}, "unexpected message received: ChannelFailure (100)"sv},
                           {wire::PingMsg{}, ""sv},
                           {wire::PongMsg{}, ""sv},
                         }));

class ServerTransportLoadHostKeysTest : public ServerTransportTest {
public:
  void SetUp() override {}
};

TEST_F(ServerTransportTest, SuccessfulUserAuth_NormalMode) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectEvent();

  ASSERT_OK(WriteMsg(std::move(authReq)));
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_NormalMode_UpstreamConnectionFails) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_, _)) // header frame overload
    .WillOnce(Invoke([this](RequestHeaderFramePtr frame, absl::optional<StartTime>) {
      // Mimic what generic proxy does here: build a response frame with respond(), then pass it
      // to encode()
      GenericProxy::MockEncodingContext ctx;

      auto respHeader = transport_.respond(absl::UnavailableError("no_healthy_upstream"), "test", *frame);
      auto res = transport_.encode(*respHeader, ctx);
      EXPECT_OK(res);
    }));

  ASSERT_OK(WriteMsg(std::move(authReq)));
}

TEST_F(ServerTransportTest, ForwardGlobalRequests) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectEvent();

  ASSERT_OK(WriteMsg(std::move(authReq)));

  // When the upstream is available, some global requests should be forwarded
  wire::GlobalRequestMsg tcpipForwardMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{},
  };
  wire::GlobalRequestMsg cancelTcpipForwardMsg{
    .want_reply = true,
    .request = wire::CancelTcpipForwardMsg{},
  };
  EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(RequestCommonFrameWithMsg(tcpipForwardMsg)));
  EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(RequestCommonFrameWithMsg(cancelTcpipForwardMsg)));

  ASSERT_OK(WriteMsg(auto(tcpipForwardMsg)));
  ASSERT_OK(WriteMsg(auto(cancelTcpipForwardMsg)));
}

// NOLINTBEGIN(readability-identifier-naming)
class HijackedModeTest : public ServerTransportTest {
public:
  absl::Status SetupHijackedMode() {
    RETURN_IF_NOT_OK(ReadExtInfo());

    auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

    RETURN_IF_NOT_OK(RequestUserAuthService());
    auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

    ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);
    // no decoding success or upstream connect

    RETURN_IF_NOT_OK(WriteMsg(std::move(authReq)));
    wire::UserAuthSuccessMsg success;
    RETURN_IF_NOT_OK(ReadMsg(success));
    return absl::OkStatus();
  }

  absl::StatusOr<uint32_t> StartChannel(bool expect_failure = false,
                                        pomerium::extensions::ssh::InternalCLIModeHint expect_mode_hint = {}) {
    auto nextInternalId = transport_.channelIdManager().nextInternalIdForTest();

    // The allow response can contain metadata which will be sent back at the start of the
    // ServeChannel RPC, to help identify the stream or pass arbitrary data between the rpc handlers.
    ChannelMessage metadataReq;
    (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = Protobuf::Struct{};
    pomerium::extensions::ssh::FilterMetadata sshMetadata;
    sshMetadata.set_channel_id(nextInternalId);
    sshMetadata.set_mode_hint(expect_mode_hint);
    (*metadataReq.mutable_metadata()->mutable_typed_filter_metadata())["com.pomerium.ssh"].PackFrom(sshMetadata);

    // when the downstream sends messages, they should be written to the hijacked stream
    wire::ChannelOpenMsg open;
    open.request = wire::SessionChannelOpenMsg{};
    open.sender_channel = ++last_downstream_id_;
    open.initial_window_size = wire::ChannelWindowSize;
    open.max_packet_size = wire::ChannelMaxPacketSize;
    if (!expect_failure) {
      IN_SEQUENCE;
      ExpectSendOnServeChannelStream(metadataReq);
      ExpectSendOnServeChannelStream(open);
    }
    RETURN_IF_NOT_OK(WriteMsg(std::move(open)));

    return nextInternalId;
  }

  // note: uses the most recently started downstream ID
  void SendChannelOpenConfirmation(uint32_t internal_id, size_t stream_index = 0) {
    ASSERT(last_downstream_id_ != 0);
    SendChannelMsgToDownstream(
      internal_id,
      wire::ChannelOpenConfirmationMsg{
        .recipient_channel = last_downstream_id_,
        .sender_channel = internal_id,
        .initial_window_size = wire::ChannelWindowSize,
        .max_packet_size = wire::ChannelMaxPacketSize,
      },
      stream_index);
  }

  void SendChannelOpenFailure(size_t stream_index = 0) {
    ASSERT(last_downstream_id_ != 0);
    wire::ChannelOpenFailureMsg msg;
    msg.recipient_channel = last_downstream_id_;
    msg.reason_code = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
    msg.description = "test error"s;
    auto channelMsg = std::make_unique<ChannelMessage>();
    *channelMsg->mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(msg);
    serve_channel_callbacks_[stream_index]->onReceiveMessage(std::move(channelMsg));
  }

  absl::Status SendChannelDataFromDownstream(uint32_t internal_id, bytes data) {
    wire::ChannelDataMsg msg;
    msg.recipient_channel = internal_id;
    msg.data = std::move(data);
    ExpectSendOnServeChannelStream(msg);
    return WriteMsg(std::move(msg));
  }

  // To check for errors here, use
  // EXPECT_CALL(server_codec_callbacks_, onDecodingFailure(...));
  void SendChannelDataToDownstream(uint32_t internal_id, bytes data, size_t stream_index = 0) {
    wire::ChannelDataMsg msg;
    msg.recipient_channel = internal_id;
    msg.data = std::move(data);

    auto channelMsg = std::make_unique<ChannelMessage>();
    *channelMsg->mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(msg);
    serve_channel_callbacks_[stream_index]->onReceiveMessage(std::move(channelMsg));
  }

  void SendChannelMsgToDownstream(uint32_t internal_id, wire::ChannelMsg auto&& msg, size_t stream_index = 0) {
    msg.recipient_channel = internal_id;
    auto channelMsg = std::make_unique<ChannelMessage>();
    *channelMsg->mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(msg);
    serve_channel_callbacks_[stream_index]->onReceiveMessage(std::move(channelMsg));
  }

private:
  uint32_t last_downstream_id_ = 0;
};
// NOLINTEND(readability-identifier-naming)

TEST_F(HijackedModeTest, HijackedMode) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());
  SendChannelOpenConfirmation(*channel1);

  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  ASSERT_OK(SendChannelDataFromDownstream(*channel1, "ping"_bytes));
  SendChannelDataToDownstream(*channel1, "pong"_bytes);

  wire::ChannelDataMsg msg;
  ASSERT_OK(ReadMsg(msg));
  ASSERT_EQ(msg.recipient_channel, 1u);
  ASSERT_EQ(msg.data, "pong"_bytes);
}

TEST_F(HijackedModeTest, HijackedMode_AddWellKnownMetadata) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg, true); // sets stream_id in metadata
  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = Protobuf::Struct{};
  pomerium::extensions::ssh::FilterMetadata sshMetadata;
  sshMetadata.set_channel_id(transport_.channelIdManager().nextInternalIdForTest());
  sshMetadata.set_stream_id(999); // the stream_id should be passed through
  (*metadataReq.mutable_metadata()->mutable_typed_filter_metadata())["com.pomerium.ssh"].PackFrom(sshMetadata);

  wire::ChannelOpenMsg open;
  open.request = wire::SessionChannelOpenMsg{};
  open.sender_channel = 1;
  open.initial_window_size = wire::ChannelWindowSize;
  open.max_packet_size = wire::ChannelMaxPacketSize;
  {
    IN_SEQUENCE;
    ExpectSendOnServeChannelStream(metadataReq);
    ExpectSendOnServeChannelStream(open);
  }
  ASSERT_OK(WriteMsg(std::move(open)));
}

TEST_F(HijackedModeTest, HijackedMode_ErrorStartingChannelOnChannelOpenMsg) {
  ASSERT_OK(SetupHijackedMode());
  // simulate an error that would cause the channel open to fail, such as channel exhaustion
  while (transport_.channelIdManager().allocateNewChannel(Peer::Downstream).ok())
    ;
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("error starting channel: failed to allocate ID"));
  ASSERT_OK(StartChannel(true).status()); // expect failure
}

TEST_F(HijackedModeTest, HijackedMode_WrongFirstDownstreamMessage) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("unexpected message received before channel open confirmation: ChannelData (94)"));
  wire::ChannelDataMsg msg;
  msg.recipient_channel = *channel1;
  msg.data = "ping"_bytes;
  ASSERT_OK(WriteMsg(std::move(msg)));
}

TEST_F(HijackedModeTest, HijackedMode_WrongFirstUpstreamMessage) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("expected ChannelOpenConfirmation or ChannelOpenFailure, got ChannelData (94)"));
  SendChannelMsgToDownstream(*channel1, wire::ChannelDataMsg{
                                          .recipient_channel = *channel1,
                                          .data = "invalid"_bytes,
                                        });
}

TEST_F(HijackedModeTest, HijackedMode_WrongChannelOpenConfirmation) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  SendChannelOpenConfirmation(*channel1);
  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("unexpected ChannelOpenConfirmation message"));
  SendChannelOpenConfirmation(*channel1);
}

TEST_F(HijackedModeTest, HijackedMode_WrongChannelOpenFailure) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  SendChannelOpenConfirmation(*channel1);
  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("unexpected ChannelOpenFailure message"));
  SendChannelOpenFailure();
}

TEST_F(HijackedModeTest, HijackedMode_OpenChannelFromUpstreamUnimplemented) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  SendChannelOpenConfirmation(*channel1);
  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("cannot open channels from a hijacked stream"));
  wire::ChannelOpenMsg msg;
  msg.sender_channel = 12345;
  msg.channel_type() = "foo"s;
  auto channelMsg = std::make_unique<ChannelMessage>();
  *channelMsg->mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(msg);
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_UnknownMessageFromUpstream) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  SendChannelOpenConfirmation(*channel1);
  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received unknown channel message: 110")); // 'n'=110
  auto channelMsg = std::make_unique<ChannelMessage>();
  *channelMsg->mutable_raw_bytes()->mutable_value() = "not a message";
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_InvalidMessageFromUpstream) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  SendChannelOpenConfirmation(*channel1);
  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: short read"));
  auto channelMsg = std::make_unique<ChannelMessage>();
  *channelMsg->mutable_raw_bytes()->mutable_value() = {static_cast<char>(94)};
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_MultipleChannels) {
  ASSERT_OK(SetupHijackedMode());

  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());
  SendChannelOpenConfirmation(*channel1, 0); // grpc stream 0

  {
    wire::ChannelOpenConfirmationMsg confirm;
    ASSERT_OK(ReadMsg(confirm));
  }

  {
    ASSERT_OK(SendChannelDataFromDownstream(*channel1, "ping 1"_bytes));
    SendChannelDataToDownstream(*channel1, "pong 1"_bytes, 0);
    wire::ChannelDataMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(msg.recipient_channel, 1u);
    ASSERT_EQ(msg.data, "pong 1"_bytes);
  }

  // open a second channel
  auto channel2 = StartChannel();
  ASSERT_OK(channel2.status());
  SendChannelOpenConfirmation(*channel2, 1); // grpc stream 1
  {
    wire::ChannelOpenConfirmationMsg confirm;
    ASSERT_OK(ReadMsg(confirm));
  }

  {
    ASSERT_OK(SendChannelDataFromDownstream(*channel2, "ping 2"_bytes));
    SendChannelDataToDownstream(*channel2, "pong 2"_bytes, 1);
    wire::ChannelDataMsg msg2;
    ASSERT_OK(ReadMsg(msg2));
    ASSERT_EQ(msg2.recipient_channel, 2u);
    ASSERT_EQ(msg2.data, "pong 2"_bytes);
  }

  {
    SendChannelDataToDownstream(*channel1, "more data for channel 1"_bytes, 0);
    wire::ChannelDataMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(msg.recipient_channel, 1u);
    ASSERT_EQ(msg.data, "more data for channel 1"_bytes);
  }
}

TEST_F(HijackedModeTest, HijackedMode_ChannelOpenFailure) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());
  SendChannelOpenFailure();
  wire::ChannelOpenFailureMsg failure;
  ASSERT_OK(ReadMsg(failure));
  ASSERT_EQ(SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED, *failure.reason_code);
  ASSERT_EQ("test error", *failure.description);
}

TEST_F(HijackedModeTest, HijackedMode_InvalidChannelControlMsg) {
  ASSERT_OK(SetupHijackedMode());
  ASSERT_OK(StartChannel());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: missing control action"));
  auto channelMsg = std::make_unique<ChannelMessage>();
  channelMsg->mutable_channel_control();
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_InvalidChannelControlMsg_EmptyControlAction) {
  ASSERT_OK(SetupHijackedMode());
  ASSERT_OK(StartChannel());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: failed to unpack control action"));
  auto channelMsg = std::make_unique<ChannelMessage>();
  channelMsg->mutable_channel_control()->mutable_control_action();
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_InvalidChannelControlMsg_UnpackFailed) {
  ASSERT_OK(SetupHijackedMode());
  ASSERT_OK(StartChannel());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: failed to unpack control action"));
  auto channelMsg = std::make_unique<ChannelMessage>();
  channelMsg->mutable_channel_control()->mutable_control_action()->PackFrom(Protobuf::StringValue{});
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_InvalidChannelControlMsg_InvalidSshControlAction) {
  ASSERT_OK(SetupHijackedMode());
  ASSERT_OK(StartChannel());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: unknown action type: 0"));
  auto channelMsg = std::make_unique<ChannelMessage>();
  channelMsg->mutable_channel_control()->mutable_control_action()->PackFrom(SSHChannelControlAction{});
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_InvalidControlMsg) {
  ASSERT_OK(SetupHijackedMode());
  ASSERT_OK(StartChannel());
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: unknown message type: 0"));
  auto channelMsg = std::make_unique<ChannelMessage>();
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
}

TEST_F(HijackedModeTest, HijackedMode_InterruptConfig) {
  ASSERT_OK(SetupHijackedMode());
  auto channel1 = StartChannel();
  ASSERT_OK(channel1.status());

  SendChannelOpenConfirmation(*channel1);
  wire::ChannelOpenConfirmationMsg confirm;
  ASSERT_OK(ReadMsg(confirm));

  auto channelMsg = std::make_unique<ChannelMessage>();
  SSHChannelControlAction action;
  *action.mutable_set_interrupt_options()->mutable_send_channel_data() = "goodbye world";
  channelMsg->mutable_channel_control()->mutable_control_action()->PackFrom(action);

  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("server shutting down"));
  server_factory_context_.drainManager().startDrainSequence(Network::DrainDirection::All, [] {});
  wire::ChannelDataMsg msg;
  ASSERT_OK(ReadMsg(msg));
  ASSERT_EQ("goodbye world"_bytes, *msg.data);
  wire::DisconnectMsg serverDisconnect;
  ASSERT_OK(ReadMsg(serverDisconnect));
  EXPECT_THAT(*serverDisconnect.description, HasSubstr("server shutting down"));
  EXPECT_EQ(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, *serverDisconnect.reason_code);
}

TEST_F(HijackedModeTest, HijackedMode_NoChannelRequest) {
  ASSERT_OK(SetupHijackedMode());
  // The ServeChannel stream is only started on a ChannelOpen request after auth success. If
  // none is sent no connection should be started.
}

TEST_F(HijackedModeTest, TcpipForwardRequestSuccess) {
  ASSERT_OK(SetupHijackedMode());

  ClientMessage expectedClientMsg;
  expectedClientMsg.mutable_global_request()->set_want_reply(true);
  auto* forwardRequest = expectedClientMsg.mutable_global_request()->mutable_tcpip_forward_request();
  forwardRequest->set_remote_address("test_address");
  forwardRequest->set_remote_port(0);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(expectedClientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      // simulate the server responding
      auto response = std::make_unique<ServerMessage>();
      response->mutable_global_request_response()->set_success(true);
      response->mutable_global_request_response()->mutable_tcpip_forward_response()->set_server_port(1234);
      manage_stream_callbacks_->onReceiveMessage(std::move(response));
    });

  // This mimics the behavior of openssh client when the -R flag is used. The global request is sent
  // after UserAuthSuccess is received, and before ChannelOpen is sent.
  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{
      .remote_address = "test_address"s,
      .remote_port = 0,
    },
  }));

  wire::GlobalRequestSuccessMsg actualReply;
  ASSERT_OK(ReadMsg(actualReply));
  ASSERT_OK(actualReply.resolve<wire::TcpipForwardResponseMsg>());

  wire::GlobalRequestSuccessMsg expectedReply{
    .response = wire::TcpipForwardResponseMsg{
      .server_port = 1234,
    },
  };
  ASSERT_EQ(expectedReply, actualReply);

  // The global request is sent to the management server before the channel open request,
  // but since the messages are not sent on the same grpc stream, the management server may
  // not receive the messages in the same order. To avoid a logic race, the server transport
  // will set the mode hint in the filter metadata when the channel is opened.
  EXPECT_OK(StartChannel(false, pomerium::extensions::ssh::MODE_TUNNEL_STATUS));
}

TEST_F(HijackedModeTest, TcpipForwardRequestSuccess_NoExtraData) {
  ASSERT_OK(SetupHijackedMode());

  ClientMessage expectedClientMsg;
  expectedClientMsg.mutable_global_request()->set_want_reply(true);
  auto* forwardRequest = expectedClientMsg.mutable_global_request()->mutable_tcpip_forward_request();
  forwardRequest->set_remote_address("test_address");
  forwardRequest->set_remote_port(1234);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(expectedClientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      auto response = std::make_unique<ServerMessage>();
      response->mutable_global_request_response()->set_success(true);
      // no message-specific extra data
      manage_stream_callbacks_->onReceiveMessage(std::move(response));
    });

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{
      .remote_address = "test_address"s,
      .remote_port = 1234,
    },
  }));

  wire::GlobalRequestSuccessMsg expectedReply; // should be empty
  ASSERT_OK(ReadMsg(expectedReply));
  ASSERT_FALSE(expectedReply.response.has_value());
  ASSERT_FALSE(expectedReply.response.has_unknown_value());
}

TEST_F(HijackedModeTest, TcpipForwardRequestFailure) {
  ASSERT_OK(SetupHijackedMode());

  ClientMessage expectedClientMsg;
  expectedClientMsg.mutable_global_request()->set_want_reply(true);
  auto* forwardRequest = expectedClientMsg.mutable_global_request()->mutable_tcpip_forward_request();
  forwardRequest->set_remote_address("test_address");
  forwardRequest->set_remote_port(1234);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(expectedClientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      auto response = std::make_unique<ServerMessage>();
      response->mutable_global_request_response()->set_success(false);
      manage_stream_callbacks_->onReceiveMessage(std::move(response));
    });

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{
      .remote_address = "test_address"s,
      .remote_port = 1234,
    },
  }));

  wire::GlobalRequestFailureMsg expectedReply;
  ASSERT_OK(ReadMsg(expectedReply));
}

TEST_F(HijackedModeTest, TcpipForwardRequestFailureWithDebugMessage) {
  ASSERT_OK(SetupHijackedMode());

  ClientMessage expectedClientMsg;
  expectedClientMsg.mutable_global_request()->set_want_reply(true);
  auto* forwardRequest = expectedClientMsg.mutable_global_request()->mutable_tcpip_forward_request();
  forwardRequest->set_remote_address("test_address");
  forwardRequest->set_remote_port(1234);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(expectedClientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      auto response = std::make_unique<ServerMessage>();
      response->mutable_global_request_response()->set_success(false);
      response->mutable_global_request_response()->set_debug_message("test debug message");
      manage_stream_callbacks_->onReceiveMessage(std::move(response));
    });

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{
      .remote_address = "test_address"s,
      .remote_port = 1234,
    },
  }));

  wire::DebugMsg debugMsg;
  ASSERT_OK(ReadMsg(debugMsg));
  EXPECT_EQ("test debug message", *debugMsg.message);
  EXPECT_TRUE(debugMsg.always_display);

  wire::GlobalRequestFailureMsg expectedReply;
  ASSERT_OK(ReadMsg(expectedReply));
}

TEST_F(HijackedModeTest, TcpipForwardRequestInvalidServerMessage) {
  ASSERT_OK(SetupHijackedMode());

  ClientMessage expectedClientMsg;
  expectedClientMsg.mutable_global_request()->set_want_reply(true);
  expectedClientMsg.mutable_global_request()->mutable_tcpip_forward_request();

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(expectedClientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      auto response = std::make_unique<ServerMessage>();
      manage_stream_callbacks_->onReceiveMessage(std::move(response));
    });

  // this should fail at the message dispatcher level
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure(fmt::format("management server error: unexpected message received: {}",
                                                                     ServerMessage::MessageCase::MESSAGE_NOT_SET)));
  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::TcpipForwardMsg{},
  }));
}

TEST_F(HijackedModeTest, CancelTcpipForwardRequest) {
  ASSERT_OK(SetupHijackedMode());

  ClientMessage expectedClientMsg;
  expectedClientMsg.mutable_global_request()->set_want_reply(true);
  auto* forwardRequest = expectedClientMsg.mutable_global_request()->mutable_cancel_tcpip_forward_request();
  forwardRequest->set_remote_address("test_address");
  forwardRequest->set_remote_port(1234);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(expectedClientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      auto response = std::make_unique<ServerMessage>();
      response->mutable_global_request_response()->set_success(true);
      manage_stream_callbacks_->onReceiveMessage(std::move(response));
    });

  ASSERT_OK(WriteMsg(wire::GlobalRequestMsg{
    .want_reply = true,
    .request = wire::CancelTcpipForwardMsg{
      .remote_address = "test_address"s,
      .remote_port = 1234,
    },
  }));

  wire::GlobalRequestSuccessMsg actualReply;
  ASSERT_OK(ReadMsg(actualReply));
  ASSERT_FALSE(actualReply.response.has_value());
  ASSERT_FALSE(actualReply.response.has_unknown_value());
}

// NOLINTBEGIN(readability-identifier-naming)
class HandoffTest : public ServerTransportTest {
public:
  absl::Status PrepareHandoff() {
    RETURN_IF_NOT_OK(ReadExtInfo());

    auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

    RETURN_IF_NOT_OK(RequestUserAuthService());
    auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

    ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);

    RETURN_IF_NOT_OK(WriteMsg(std::move(authReq)));
    wire::UserAuthSuccessMsg success;
    RETURN_IF_NOT_OK(ReadMsg(success));

    ChannelMessage metadataReq;
    (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = Protobuf::Struct{};
    pomerium::extensions::ssh::FilterMetadata sshMetadata;
    sshMetadata.set_channel_id(100);
    (*metadataReq.mutable_metadata()->mutable_typed_filter_metadata())["com.pomerium.ssh"].PackFrom(sshMetadata);

    // when the downstream opens a channel, it should start a new stream
    wire::ChannelOpenMsg open;
    open.request = wire::SessionChannelOpenMsg{};
    open.sender_channel = 1;
    open.initial_window_size = wire::ChannelWindowSize;
    open.max_packet_size = wire::ChannelMaxPacketSize;
    {
      IN_SEQUENCE;
      ExpectSendOnServeChannelStream(metadataReq);
      ExpectSendOnServeChannelStream(open);
    }
    RETURN_IF_NOT_OK(WriteMsg(std::move(open)));
    return absl::OkStatus();
  }

  void SendChannelOpenConfirmation() {
    // bind the upstream channel to simulate the handoff
    ASSERT_OK(transport_.channelIdManager().bindChannelID(100,
                                                          PeerLocalID{
                                                            .channel_id = 2,
                                                            .local_peer = Peer::Upstream,
                                                          }));
    auto channelMsg = std::make_unique<ChannelMessage>();
    auto confirmation = wire::ChannelOpenConfirmationMsg{
      .recipient_channel = 100,
      .sender_channel = 100,
      .initial_window_size = wire::ChannelWindowSize,
      .max_packet_size = wire::ChannelMaxPacketSize,
    };
    *channelMsg->mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(confirmation);
    serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));
  }

  ChannelMessage BuildHandOffChannelMessage() {
    ChannelMessage ctrl;
    SSHChannelControlAction action;
    auto* handoff = action.mutable_hand_off();
    auto* downstreamInfo = handoff->mutable_downstream_channel_info();
    downstreamInfo->set_downstream_channel_id(1);
    downstreamInfo->set_internal_upstream_channel_id(100);
    downstreamInfo->set_channel_type("session");
    downstreamInfo->set_initial_window_size(wire::ChannelWindowSize);
    downstreamInfo->set_max_packet_size(wire::ChannelMaxPacketSize);
    auto* ptyInfo = handoff->mutable_downstream_pty_info();
    ptyInfo->set_term_env("xterm-256color");
    ptyInfo->set_height_rows(24);
    ptyInfo->set_width_columns(80);
    auto* allow = handoff->mutable_upstream_auth();
    allow->set_username("test");
    auto* upstream = allow->mutable_upstream();
    *upstream->mutable_hostname() = "example";
    *upstream->add_allowed_methods()->mutable_method() = "publickey";
    ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
    return ctrl;
  }
};

// NOLINTEND(readability-identifier-naming)

TEST_F(HandoffTest, HandoffMode) {
  ASSERT_OK(PrepareHandoff());
  SendChannelOpenConfirmation();
  ExpectUpstreamConnectEvent();
  EXPECT_CALL(mock_connection_, readDisable(true));
  ExpectDecodingSuccess();
  ReceiveOnServeChannelStream(BuildHandOffChannelMessage());

  // any messages sent by the downstream after handoff should be forwarded
  EXPECT_CALL(server_codec_callbacks_,
              onDecodingSuccess(
                RequestCommonFrameWithMsg(wire::ChannelDataMsg{
                  .recipient_channel = 2,
                  .data = "hello world"_bytes,
                }))); // 1-arg overload
  ASSERT_OK(WriteMsg(wire::ChannelDataMsg{
    .recipient_channel = 100,
    .data = "hello world"_bytes,
  }));
}

TEST_F(HandoffTest, HandoffMode_Mirror) {
  ASSERT_OK(PrepareHandoff());
  SendChannelOpenConfirmation();
  ChannelMessage ctrl;
  SSHChannelControlAction action;
  auto* handoff = action.mutable_hand_off();
  auto* allow = handoff->mutable_upstream_auth();
  allow->set_username("test");
  allow->mutable_mirror_session();
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("session mirroring feature not available"));
  ReceiveOnServeChannelStream(ctrl);
}

TEST_F(HandoffTest, HandoffMode_Internal) {
  ASSERT_OK(PrepareHandoff());
  SendChannelOpenConfirmation();
  ChannelMessage ctrl;
  SSHChannelControlAction action;
  auto* handoff = action.mutable_hand_off();
  auto* allow = handoff->mutable_upstream_auth();
  allow->set_username("test");
  allow->mutable_internal();
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received invalid channel message: unexpected target: 3"));
  ReceiveOnServeChannelStream(ctrl);
}

TEST_F(HandoffTest, HandoffMode_StartHandoffBeforeChannelOpenConfirmation) {
  ASSERT_OK(PrepareHandoff());
  SSHChannelControlAction action;
  action.mutable_hand_off(); // any handoff message should trigger this error, contents don't matter
  ChannelMessage ctrl;
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("handoff requested before channel open confirmation"));
  ReceiveOnServeChannelStream(ctrl);
}

TEST_F(HandoffTest, HandoffMode_StartDirectTcpipHandoffBeforeChannelOpenConfirmation) {
  ASSERT_OK(PrepareHandoff());
  SSHChannelControlAction action;
  action.mutable_hand_off()->mutable_upstream_auth()->mutable_upstream()->set_direct_tcpip(true);
  ChannelMessage ctrl;
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  ExpectUpstreamConnectEvent();
  ExpectDecodingSuccess(""); // empty host for direct-tcpip
  ReceiveOnServeChannelStream(ctrl);
}

TEST_F(HandoffTest, HandoffMode_StartDirectTcpipHandoffAfterChannelOpenConfirmation) {
  ASSERT_OK(PrepareHandoff());
  SendChannelOpenConfirmation();
  SSHChannelControlAction action;
  action.mutable_hand_off()->mutable_upstream_auth()->mutable_upstream()->set_direct_tcpip(true);
  ChannelMessage ctrl;
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("direct-tcpip handoff requested after channel open confirmation"));
  ReceiveOnServeChannelStream(ctrl);
}

TEST_F(HandoffTest, HandoffMode_UpstreamConnectionFails) {
  ASSERT_OK(PrepareHandoff());
  SendChannelOpenConfirmation();

  EXPECT_CALL(mock_connection_, readDisable(true));
  EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_, _)) // header frame overload
    .WillOnce(Invoke([this](RequestHeaderFramePtr frame, absl::optional<StartTime>) {
      GenericProxy::MockEncodingContext ctx;
      auto respHeader = transport_.respond(absl::UnavailableError("no_healthy_upstream"), "test", *frame);
      auto res = transport_.encode(*respHeader, ctx);
      EXPECT_OK(res);
    }));

  ReceiveOnServeChannelStream(BuildHandOffChannelMessage());
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_MirrorMode) {
  auto state = std::make_shared<AuthInfo>();
  state->channel_mode = ChannelMode::Mirror;
#ifndef SSH_EXPERIMENTAL
  EXPECT_THROW_WITH_MESSAGE(transport_.initUpstream(state),
                            EnvoyException,
                            "mirroring not supported");
#else
  EXPECT_NO_THROW(transport_.initUpstream(state));
#endif
}

TEST_F(ServerTransportTest, HijackedMode_StreamClosed) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);

  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = Protobuf::Struct{};
  pomerium::extensions::ssh::FilterMetadata sshMetadata;
  sshMetadata.set_channel_id(100);
  (*metadataReq.mutable_metadata()->mutable_typed_filter_metadata())["com.pomerium.ssh"].PackFrom(sshMetadata);

  // open a new channel to start the hijacked connection
  wire::ChannelOpenMsg open;
  open.request = wire::SessionChannelOpenMsg{};
  open.sender_channel = 1;
  open.initial_window_size = wire::ChannelWindowSize;
  open.max_packet_size = wire::ChannelMaxPacketSize;
  {
    IN_SEQUENCE;
    ExpectSendOnServeChannelStream(metadataReq);
    ExpectSendOnServeChannelStream(open);
  }
  ASSERT_OK(WriteMsg(std::move(open)));

  // If the stream is closed unexpectedly, it should end the connection
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("test error"));
  serve_channel_callbacks_[0]->onRemoteClose(Envoy::Grpc::Status::Internal, "test error");
  wire::DisconnectMsg serverDisconnect;
  ASSERT_OK(ReadMsg(serverDisconnect));
  EXPECT_EQ(statusToString(absl::InternalError("test error")), serverDisconnect.description);
  EXPECT_EQ(openssh::statusCodeToDisconnectCode(absl::StatusCode::kInternal), serverDisconnect.reason_code);
}

TEST_F(ServerTransportTest, PomeriumDisconnectsDuringAuth) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(clientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      manage_stream_callbacks_->onRemoteClose(Envoy::Grpc::Status::Internal, "test error");
    });

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("management server error: test error"));
  ASSERT_OK(WriteMsg(std::move(authReq)));
}

TEST_F(ServerTransportTest, PomeriumDisconnectsDuringAuthWithPermissionDenied) {
  // PermissionDenied is a special case, it won't prepend the "management server error" prefix
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(ProtoBufferStrictEq(clientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      manage_stream_callbacks_->onRemoteClose(Envoy::Grpc::Status::PermissionDenied, "not authorized");
    });

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("not authorized"));
  ASSERT_OK(WriteMsg(std::move(authReq)));
}

TEST_F(ServerTransportTest, InvalidMessageReceived) {
  // Can't happen under normal circumstances, but still a possible error
  EXPECT_EQ(absl::InternalError("received invalid message: UserAuthRequest (50)"),
            transport_.handleMessage(wire::Message{wire::UserAuthRequestMsg{}}));
}

class ClientMessagesPostUserAuthTest : public ServerTransportTest,
                                       public testing::WithParamInterface<std::tuple<wire::Message, std::string_view>> {
  void SetUp() override {
    ServerTransportTest::SetUp();

    ASSERT_OK(ReadExtInfo());
    auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

    ASSERT_OK(RequestUserAuthService());
    auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

    ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
    ExpectDecodingSuccess();
    ExpectUpstreamConnectEvent();

    ASSERT_OK(WriteMsg(std::move(authReq)));
  }
};

TEST_P(ClientMessagesPostUserAuthTest, ClientMessagesPostUserAuth) {
  // After user auth is complete:
  // - the client is allowed to make requests to the connection service
  // - the client is *not* allowed to make requests to the user auth service (at least currently)
  // - global requests will be forwarded to the upstream

  auto [msg, err] = GetParam();
  if (err != "") {
    EXPECT_CALL(server_codec_callbacks_, onDecodingFailure(_))
      .WillOnce([err](std::string_view actual) {
        EXPECT_THAT(actual, HasSubstr(err));
      });
  } else {
    msg.visit(
      [this](wire::ChannelMsg auto const&) {
        EXPECT_CALL(server_codec_callbacks_, onDecodingFailure(_)); // common frame overload
      },
      [this](const wire::ChannelOpenMsg&) {
        EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_));
      },
      [this](const wire::GlobalRequestMsg& req) {
        // we still handle HostKeysProve
        if (!req.request.holds_alternative<wire::HostKeysProveRequestMsg>()) {
          EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_));
        }
      },
      [this](const wire::GlobalRequestSuccessMsg&) {
        EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_));
      },
      [this](const wire::GlobalRequestFailureMsg&) {
        EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_));
      },
      [](const auto&) {});
  }
  ASSERT_OK(WriteMsg(std::move(msg)));
  if (err != "") {
    // for KexInitMsg, the server sends its KexInit reply before checking the algorithms
    if (msg.msg_type() == wire::SshMessageType::KexInit) {
      wire::KexInitMsg serverKexInit;
      ASSERT_OK(ReadMsg(serverKexInit));
    }
    wire::DisconnectMsg serverDisconnect;
    ASSERT_OK(ReadMsg(serverDisconnect));
    EXPECT_THAT(*serverDisconnect.description, HasSubstr(err));
    EXPECT_EQ(2 /*SSH2_DISCONNECT_PROTOCOL_ERROR*/, *serverDisconnect.reason_code);
  }
}

INSTANTIATE_TEST_SUITE_P(ClientMessagesPostUserAuth, ClientMessagesPostUserAuthTest,
                         testing::ValuesIn(std::vector<std::tuple<wire::Message, std::string_view>>{
                           {wire::ServiceRequestMsg{.service_name = "ssh-userauth"s}, "unexpected message received: ServiceRequest (5)"sv},
                           {wire::ServiceRequestMsg{.service_name = "ssh-connection"s}, "unexpected message received: ServiceRequest (5)"sv},
                           {wire::GlobalRequestMsg{.request = {wire::HostKeysProveRequestMsg{}}}, ""sv},
                           {wire::GlobalRequestMsg{}, ""sv},
                           {wire::GlobalRequestMsg{.request = {wire::HostKeysMsg{}}}, "unexpected global request: hostkeys-00@openssh.com"sv},
                           {wire::GlobalRequestSuccessMsg{}, ""sv},
                           {wire::GlobalRequestFailureMsg{}, ""sv},
                           {wire::IgnoreMsg{.data = "foo"_bytes}, ""sv},
                           {wire::DebugMsg{.message = "foo"s}, ""sv},
                           {wire::UnimplementedMsg{.sequence_number = 1234}, ""sv},
                           {wire::ExtInfoMsg{}, "unexpected message received: ExtInfo (7)"sv},
                           {wire::KexInitMsg{}, "no common algorithm for key exchange; client offered: []; server offered: [\"mlkem768x25519-sha256\", \"curve25519-sha256\", \"curve25519-sha256@libssh.org\"]"sv},

                           {wire::ServiceAcceptMsg{}, "unexpected message received: ServiceAccept (6)"sv},
                           {wire::NewKeysMsg{}, "unexpected message received: NewKeys (21)"sv},
                           {wire::UserAuthRequestMsg{}, "unexpected message received: UserAuthRequest (50)"sv},
                           {wire::UserAuthFailureMsg{}, "unexpected message received: UserAuthFailure (51)"sv},
                           {wire::UserAuthSuccessMsg{}, "unexpected message received: UserAuthSuccess (52)"sv},
                           {wire::UserAuthBannerMsg{}, "unexpected message received: UserAuthBanner (53)"sv},
                           {wire::ChannelOpenMsg{}, ""sv},
                           {wire::ChannelOpenConfirmationMsg{}, "received invalid ChannelOpenConfirmation message: unknown channel 0"sv},
                           {wire::ChannelOpenFailureMsg{}, "received invalid ChannelOpenFailure message: unknown channel 0"sv},
                           {wire::ChannelWindowAdjustMsg{}, "received message for unknown channel 0: ChannelWindowAdjust"sv},
                           {wire::ChannelDataMsg{}, "received message for unknown channel 0: ChannelData"sv},
                           {wire::ChannelExtendedDataMsg{}, "received message for unknown channel 0: ChannelExtendedData"sv},
                           {wire::ChannelEOFMsg{}, "received message for unknown channel 0: ChannelEOF"sv},
                           {wire::ChannelCloseMsg{}, "received message for unknown channel 0: ChannelClose"sv},
                           {wire::ChannelRequestMsg{}, "received message for unknown channel 0: ChannelRequest"sv},
                           {wire::ChannelSuccessMsg{}, "received message for unknown channel 0: ChannelSuccess"sv},
                           {wire::ChannelFailureMsg{}, "received message for unknown channel 0: ChannelFailure"sv},
                           {wire::PingMsg{}, ""sv},
                           {wire::PongMsg{}, ""sv},
                         }));

TEST_F(ServerTransportTest, EncodeEffectiveHeader) {
  ASSERT_OK(ReadExtInfo());
  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectEvent();
  ASSERT_OK(WriteMsg(std::move(authReq)));

  GenericProxy::MockEncodingContext ctx;
  SSHResponseCommonFrame frame(wire::IgnoreMsg{}, EffectiveHeader);

  EXPECT_CALL(server_codec_callbacks_, writeToConnection(_));
  ASSERT_OK(transport_.encode(frame, ctx).status());
}

TEST_F(ServerTransportTest, EncodeEffectiveHeaderSentinel) {
  ASSERT_OK(ReadExtInfo());
  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectEvent();
  ASSERT_OK(WriteMsg(std::move(authReq)));

  GenericProxy::MockEncodingContext ctx;
  SSHResponseCommonFrame frame(wire::IgnoreMsg{}, FrameTags(EffectiveHeader | Sentinel));

  ASSERT_OK(transport_.encode(frame, ctx).status());
}

TEST_F(ServerTransportTest, EncodeEffectiveHeaderEnablePingForwarding) {
  wire::ExtInfoMsg serverExtInfo;
  ASSERT_OK(ReadMsg(serverExtInfo));
  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectEvent();
  ASSERT_OK(WriteMsg(std::move(authReq)));

  // cheat: this is normally set by upstream user auth service
  transport_.authInfo().upstream_ext_info = serverExtInfo;

  GenericProxy::MockEncodingContext ctx;
  SSHResponseCommonFrame frame(wire::IgnoreMsg{}, EffectiveHeader);

  EXPECT_CALL(server_codec_callbacks_, writeToConnection(_));
  ASSERT_OK(transport_.encode(frame, ctx).status());
}

TEST_F(ServerTransportTest, EncodeEffectiveHeaderHandoffComplete) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);

  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = Protobuf::Struct{};
  pomerium::extensions::ssh::FilterMetadata sshMetadata;
  sshMetadata.set_channel_id(transport_.channelIdManager().nextInternalIdForTest());
  (*metadataReq.mutable_metadata()->mutable_typed_filter_metadata())["com.pomerium.ssh"].PackFrom(sshMetadata);

  wire::ChannelOpenMsg open;
  open.request = wire::SessionChannelOpenMsg{};
  open.sender_channel = 1;
  open.initial_window_size = wire::ChannelWindowSize;
  open.max_packet_size = wire::ChannelMaxPacketSize;
  {
    IN_SEQUENCE;
    ExpectSendOnServeChannelStream(metadataReq);
    ExpectSendOnServeChannelStream(open);
  }
  ASSERT_OK(WriteMsg(std::move(open)));

  // bind the upstream channel to simulate the handoff
  ASSERT_OK(transport_.channelIdManager().bindChannelID(100,
                                                        PeerLocalID{
                                                          .channel_id = 2,
                                                          .local_peer = Peer::Upstream,
                                                        }));
  auto channelMsg = std::make_unique<ChannelMessage>();
  auto confirmation = wire::ChannelOpenConfirmationMsg{
    .recipient_channel = 100,
    .sender_channel = 100,
    .initial_window_size = wire::ChannelWindowSize,
    .max_packet_size = wire::ChannelMaxPacketSize,
  };
  *channelMsg->mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(confirmation);
  serve_channel_callbacks_[0]->onReceiveMessage(std::move(channelMsg));

  ExpectUpstreamConnectEvent();

  ChannelMessage ctrl;
  SSHChannelControlAction action;
  auto* allow = action.mutable_hand_off()->mutable_upstream_auth();
  allow->set_username("test");
  auto* upstream = allow->mutable_upstream();
  *upstream->mutable_hostname() = "example";
  *upstream->add_allowed_methods()->mutable_method() = "publickey";
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(mock_connection_, readDisable(true));
  ExpectDecodingSuccess();
  ReceiveOnServeChannelStream(ctrl);

  GenericProxy::MockEncodingContext ctx;
  SSHResponseCommonFrame frame(wire::IgnoreMsg{}, FrameTags(EffectiveHeader | Sentinel));

  EXPECT_CALL(mock_connection_, readDisable(false));
  ASSERT_OK(transport_.encode(frame, ctx).status());
}

TEST_F(ServerTransportTest, EncodeEffectiveCommon) {
  GenericProxy::MockEncodingContext ctx;
  SSHResponseCommonFrame frame(wire::IgnoreMsg{}, EffectiveCommon);
  EXPECT_CALL(server_codec_callbacks_, writeToConnection(_));
  ASSERT_OK(transport_.encode(frame, ctx).status());
}

class ServerTransportResponseCodeTest : public ServerTransportTest,
                                        public testing::WithParamInterface<std::tuple<std::string_view, uint32_t>> {};

TEST_P(ServerTransportResponseCodeTest, ResponseHeaderFrameFlags) {
  auto [msg, expectedCode] = GetParam();
  auto authInfo = std::make_shared<AuthInfo>();
  authInfo->stream_id = 1234;
  SetAuthInfo(authInfo);
  SSHRequestHeaderFrame mockHeaderFrame("example", 1234);
  auto status = absl::Status(absl::StatusCode::kInternal, msg);
  auto responseFrame = transport_.respond(status, "", mockHeaderFrame);
  // The header frame returned by respond() should have end_stream and drain_close set. This is
  // somewhat of a special case - the generic proxy framework requires at least end_stream set,
  // which we normally do not set for response header frames (they are required to be the first
  // frame sent to the downstream, but are usually not the last frame sent). respond() is called
  // by generic proxy in a few cases, e.g. if the upstream fails. In those cases, the frame must
  // have end_stream set, otherwise an error will be raised and the connection will stall.
  ASSERT_EQ(ResponseHeader, responseFrame->frameFlags().frameTags());
  ASSERT_EQ(1234, responseFrame->frameFlags().streamId());
  ASSERT_TRUE(responseFrame->frameFlags().endStream());
  ASSERT_TRUE(responseFrame->frameFlags().drainClose());

  auto dc = extractFrameMessage(*responseFrame);
  dc.visit(
    [&](const wire::DisconnectMsg& dc) {
      EXPECT_EQ(expectedCode, *dc.reason_code);
      EXPECT_EQ(statusToString(status), dc.description);
    },
    [](const auto&) {
      FAIL() << "wrong message type";
    });
}

TEST_P(ServerTransportResponseCodeTest, RespondAdditionalMessage) {
  auto [msg, expectedCode] = GetParam();
  auto authInfo = std::make_shared<AuthInfo>();
  authInfo->stream_id = 1234;
  SetAuthInfo(authInfo);
  SSHRequestHeaderFrame mockHeaderFrame("example", 1234);
  auto status = absl::Status(absl::StatusCode::kInternal, msg);
  auto responseFrame = transport_.respond(status, "additional message", mockHeaderFrame);
  auto dc = extractFrameMessage(*responseFrame);
  dc.visit(
    [&](const wire::DisconnectMsg& dc) {
      EXPECT_EQ(expectedCode, dc.reason_code);
      auto expectedMsg = fmt::format("{}: [additional message]", statusToString(status));
      EXPECT_EQ(expectedMsg, dc.description);
    },
    [](const auto&) {
      FAIL() << "wrong message type";
    });
}

INSTANTIATE_TEST_SUITE_P(ServerTransportResponseCode, ServerTransportResponseCodeTest,
                         testing::ValuesIn(std::vector<std::tuple<std::string_view, uint32_t>>{
                           {"cluster_not_found", SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT},
                           {"route_not_found", SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT},
                           {"cluster_maintain_mode", SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE},
                           {"no_healthy_upstream", SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE},
                           {"timeout", SSH2_DISCONNECT_CONNECTION_LOST},
                           {"local_reset", SSH2_DISCONNECT_CONNECTION_LOST},
                           {"connection_termination", SSH2_DISCONNECT_CONNECTION_LOST},
                           {"protocol_error", SSH2_DISCONNECT_PROTOCOL_ERROR},
                           {"anything else", SSH2_DISCONNECT_BY_APPLICATION},
                         }));

TEST_F(ServerTransportTest, HandleRekey) {
  ASSERT_OK(ReadExtInfo());
  ASSERT_OK(WriteMsg(auto(kex_init_)));

  wire::KexInitMsg serverKexInit;
  ASSERT_OK(ReadMsg(serverKexInit));
  HandshakeMagics magics{
    .client_version = "SSH-2.0-TestClient"_bytes,
    .server_version = "SSH-2.0-Envoy"_bytes,
    .client_kex_init = *wire::encodeTo<bytes>(kex_init_),
    .server_kex_init = *wire::encodeTo<bytes>(serverKexInit),
  };
  DirectionalPacketCipherFactoryRegistry reg;
  reg.registerType<Chacha20Poly1305CipherFactory>();
  Curve25519Sha256KexAlgorithmFactory f;
  auto kexAlg = f.create(&magics, &kex_algs_, client_host_key_.get());
  ASSERT_OK(WriteMsg(kexAlg->buildClientInit()));
  wire::Message serverEcdhReply;
  ASSERT_OK(ReadMsg(serverEcdhReply));
  // the test is over after this, ignore the cipher
  ASSERT_OK(kexAlg->handleClientRecv(serverEcdhReply).status());
  ASSERT_OK(WriteMsg(wire::NewKeysMsg{}));
  wire::NewKeysMsg serverNewKeys;
  ASSERT_OK(ReadMsg(serverNewKeys));
  ASSERT_EQ(0, output_buffer_.length()); // there should be no ExtInfo sent
}

class StreamTrackerConnectionCallbacksTest : public ServerTransportTest,
                                             public testing::WithParamInterface<Network::ConnectionEvent> {};

TEST_P(StreamTrackerConnectionCallbacksTest, TestDisconnectEvent) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  EXPECT_CALL(mock_connection_, addConnectionCallbacks(_));
  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectEvent();

  ASSERT_OK(WriteMsg(std::move(authReq)));

  auto st = StreamTracker::fromContext(server_factory_context_);
  auto streamId = transport_.streamId();
  // ensure the connection is tracked
  CHECK_CALLED({
    st->tryLock(streamId, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_TRUE(sc.has_value());
    });
  });

  // send a disconnect event (either local or remote should do the same thing)
  mock_connection_.raiseEvent(GetParam());

  // ensure the tracked connection was ended
  CHECK_CALLED({
    st->tryLock(streamId, [&](Envoy::OptRef<StreamContext> sc) {
      CALLED;
      ASSERT_FALSE(sc.has_value());
    });
  });

  // no-op Network::ConnectionCallbacks methods, for coverage only
  transport_.onAboveWriteBufferHighWatermark();
  transport_.onBelowWriteBufferLowWatermark();
}

INSTANTIATE_TEST_SUITE_P(StreamTrackerConnectionCallbacks, StreamTrackerConnectionCallbacksTest,
                         testing::Values(Network::ConnectionEvent::LocalClose,
                                         Network::ConnectionEvent::RemoteClose));

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec