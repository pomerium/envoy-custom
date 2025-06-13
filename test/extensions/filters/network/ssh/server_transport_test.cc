
#include "source/extensions/filters/network/ssh/server_transport.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h" // IWYU pragma: keep
#include "test/extensions/filters/network/ssh/test_mocks.h"              // IWYU pragma: keep
#include "test/mocks/network/connection.h"
#include "test/mocks/grpc/mocks.h"
#include "test/test_common/test_common.h"
#include "source/extensions/filters/network/ssh/service_connection.h" // IWYU pragma: keep
#include "source/extensions/filters/network/ssh/service_userauth.h"   // IWYU pragma: keep
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
      : api_(Api::createApiForTest()),
        client_host_key_(*openssh::SSHKey::generate(KEY_ED25519, 256)),
        client_(std::make_shared<testing::StrictMock<Grpc::MockAsyncClient>>()),
        transport_(*api_, initConfig(), [this] { return this->client_; }, nullptr) {
  }

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
    ON_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
      .WillByDefault(Invoke([this](absl::string_view, absl::string_view,
                                   Envoy::Grpc::RawAsyncStreamCallbacks& callbacks,
                                   const Http::AsyncClient::StreamOptions&) {
        manage_stream_callbacks_ = dynamic_cast<Envoy::Grpc::AsyncStreamCallbacks<ServerMessage>*>(&callbacks);
        return &manage_stream_stream_;
      }));
    ON_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
      .WillByDefault(Invoke([this](absl::string_view, absl::string_view,
                                   Envoy::Grpc::RawAsyncStreamCallbacks& callbacks,
                                   const Http::AsyncClient::StreamOptions&) {
        serve_channel_callbacks_ = dynamic_cast<Envoy::Grpc::AsyncStreamCallbacks<ChannelMessage>*>(&callbacks);
        return &serve_channel_stream_;
      }));
    EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _));
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
      .client_version = "SSH-2.0-TestClient\r\n"_bytes,
      .server_version = "SSH-2.0-Envoy\r\n"_bytes,
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
    grpcAuthReq.mutable_method_request()->PackFrom(method_req);

    ClientMessage clientMsg;
    *clientMsg.mutable_auth_request() = grpcAuthReq;
    authReq.request = std::move(pubkeyReq);
    return {wire::Message{std::move(authReq)}, std::move(clientMsg)};
  }

  void ExpectHandlePomeriumGrpcAuthRequestNormal(const ClientMessage& clientMsg) {
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(Envoy::Grpc::ProtoBufferEq(clientMsg), false))
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

  void ExpectHandlePomeriumGrpcAuthRequestHijack(const ClientMessage& clientMsg) {
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(Envoy::Grpc::ProtoBufferEq(clientMsg), false))
      .WillOnce([this](Buffer::InstancePtr&, bool) {
        auto response = std::make_unique<ServerMessage>();
        auto* allow = response->mutable_auth_response()->mutable_allow();
        allow->set_username("test");
        auto* internal = allow->mutable_internal();
        (*internal->mutable_set_metadata()->mutable_filter_metadata())["foo"] = ProtobufWkt::Struct{};
        manage_stream_callbacks_->onReceiveMessage(std::move(response));
      });
  }

  void ExpectUpstreamConnectMsg() {
    ClientMessage upstreamConnectMsg{};
    upstreamConnectMsg.mutable_event()->mutable_upstream_connected()->set_stream_id(transport_.streamId());
    EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(Envoy::Grpc::ProtoBufferEq(upstreamConnectMsg), false));
  }

  void ExpectDecodingSuccess() {
    EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_, _)) // header frame overload
      .WillOnce(Invoke([this](RequestHeaderFramePtr frame, absl::optional<StartTime>) {
        ASSERT_EQ("example", frame->host());
        ASSERT_EQ("ssh", frame->protocol());
        ASSERT_EQ(transport_.streamId(), frame->frameFlags().streamId());
        ASSERT_EQ(0, frame->frameFlags().rawFlags());
        ASSERT_EQ(FrameTags::RequestHeader | FrameTags::EffectiveHeader, frame->frameFlags().frameTags());
      }));
  }

  void ExpectSendOnServeChannelStream(const ChannelMessage& msg) {
    EXPECT_CALL(serve_channel_stream_, sendMessageRaw_(Envoy::Grpc::ProtoBufferEq(msg), false));
  }

  void ExpectSendOnServeChannelStream(wire::Encoder auto const& msg) {
    ChannelMessage channelMsg;
    *channelMsg.mutable_raw_bytes()->mutable_value() = *wire::encodeTo<std::string>(msg);
    EXPECT_CALL(serve_channel_stream_, sendMessageRaw_(Envoy::Grpc::ProtoBufferEq(channelMsg), false));
  }

  void ReceiveOnServeChannelStream(const ChannelMessage& msg) {
    auto ptr = std::make_unique<ChannelMessage>(msg);
    serve_channel_callbacks_->onReceiveMessage(std::move(ptr));
  }

  auto ExpectServeChannelStart() {
    EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _));
  }

  seqnum_t read_seqnum_{};
  seqnum_t write_seqnum_{};
  std::optional<bytes> current_session_id_;
  std::unique_ptr<PacketCipher> client_cipher_;
  Envoy::Buffer::OwnedImpl input_buffer_;
  Envoy::Buffer::OwnedImpl output_buffer_;
  Api::ApiPtr api_;
  openssh::SSHKeyPtr client_host_key_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> server_config_;
  testing::StrictMock<MockServerCodecCallbacks> server_codec_callbacks_;
  testing::NiceMock<Envoy::Network::MockServerConnection> mock_connection_;
  testing::NiceMock<Grpc::MockAsyncStream> manage_stream_stream_;
  testing::NiceMock<Grpc::MockAsyncStream> serve_channel_stream_;
  std::shared_ptr<testing::StrictMock<Grpc::MockAsyncClient>> client_;
  Envoy::Grpc::AsyncStreamCallbacks<ServerMessage>* manage_stream_callbacks_;
  Envoy::Grpc::AsyncStreamCallbacks<ChannelMessage>* serve_channel_callbacks_;
  SshServerTransport transport_;

private:
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig>& initConfig() {
    server_config_ = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
    for (auto keyName : {"rsa_1", "ed25519_1"}) {
      auto hostKeyFile = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
      server_config_->add_host_keys(hostKeyFile);
    }
    return server_config_;
  }
};
// NOLINTEND(readability-identifier-naming)

TEST_F(ServerTransportTest, Disconnect) {
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received disconnect: by application"sv));

  ASSERT_OK(WriteMsg(wire::DisconnectMsg{.reason_code = 11}));
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
                           {wire::KexInitMsg{}, "no common algorithm for key exchange; client offered: []; server offered: [\"curve25519-sha256\", \"curve25519-sha256@libssh.org\"]"sv},

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

TEST_F(ServerTransportLoadHostKeysTest, LoadHostKeysError) {
  for (auto hostKey : server_config_->host_keys()) {
    chmod(hostKey.c_str(), 0644);
  }
  EXPECT_THROW_WITH_MESSAGE(transport_.setCodecCallbacks(server_codec_callbacks_),
                            EnvoyException,
                            "Invalid Argument: bad permissions");
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_NormalMode) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectMsg();

  ASSERT_OK(WriteMsg(std::move(authReq)));
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_HijackedMode) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);
  // no decoding success or upstream connect
  ExpectServeChannelStart();

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = ProtobufWkt::Struct{};
  ExpectSendOnServeChannelStream(metadataReq);

  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  // when the downstream sends messages, they should be written to the hijacked stream
  wire::ChannelOpenMsg open;
  open.channel_type = "session"s;
  open.sender_channel = 1;
  open.initial_window_size = 64 * wire::MaxPacketSize;
  open.max_packet_size = wire::MaxPacketSize;
  ExpectSendOnServeChannelStream(open);
  ASSERT_OK(WriteMsg(std::move(open)));
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_HandoffMode) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);
  // no decoding success or upstream connect
  ExpectServeChannelStart();

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = ProtobufWkt::Struct{};
  ExpectSendOnServeChannelStream(metadataReq);

  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  // when the downstream sends messages, they should be written to the hijacked stream
  wire::ChannelOpenMsg open;
  open.channel_type = "session"s;
  open.sender_channel = 1;
  open.initial_window_size = 64 * wire::MaxPacketSize;
  open.max_packet_size = wire::MaxPacketSize;
  ExpectSendOnServeChannelStream(open);
  ASSERT_OK(WriteMsg(std::move(open)));

  ExpectUpstreamConnectMsg();

  ChannelMessage ctrl;
  SSHChannelControlAction action;
  auto* allow = action.mutable_hand_off()->mutable_upstream_auth();
  allow->set_username("test");
  auto* upstream = allow->mutable_upstream();
  *upstream->mutable_hostname() = "example";
  *upstream->add_allowed_methods()->mutable_method() = "publickey";
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(mock_connection_, readDisable(true));
  EXPECT_CALL(serve_channel_stream_, resetStream);
  ExpectDecodingSuccess();
  ReceiveOnServeChannelStream(ctrl);
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_MirrorMode) {
  auto state = std::make_shared<AuthState>();
  state->channel_mode = ChannelMode::Mirror;
#ifndef SSH_EXPERIMENTAL
  EXPECT_THROW_WITH_MESSAGE(transport_.initUpstream(state),
                            EnvoyException,
                            "mirroring not supported");
#else
  EXPECT_NO_THROW(transport_.initUpstream(state));
#endif
}

TEST_F(ServerTransportTest, SuccessfulUserAuth_HijackedMode_StreamClosed) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestHijack(clientMsg);
  // no decoding success or upstream connect
  ExpectServeChannelStart();

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = ProtobufWkt::Struct{};
  ExpectSendOnServeChannelStream(metadataReq);

  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  // If the stream is closed unexpectedly, it should end the connection
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("test error"));
  serve_channel_callbacks_->onRemoteClose(Envoy::Grpc::Status::Internal, "test error");
  mock_connection_.dispatcher_.clearDeferredDeleteList(); // invoke the deferredRun callback
  wire::DisconnectMsg serverDisconnect;
  ASSERT_OK(ReadMsg(serverDisconnect));
}

TEST_F(ServerTransportTest, PomeriumDisconnectsDuringAuth) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  EXPECT_CALL(manage_stream_stream_, sendMessageRaw_(Envoy::Grpc::ProtoBufferEq(clientMsg), false))
    .WillOnce([this](Buffer::InstancePtr&, bool) {
      manage_stream_callbacks_->onRemoteClose(Envoy::Grpc::Status::Internal, "test error");
    });

  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("test error"));
  ASSERT_OK(WriteMsg(std::move(authReq)));
}

TEST_F(ServerTransportTest, HandleStreamControlDisconnect) {
  ASSERT_OK(ReadExtInfo());

  auto clientKey = *openssh::SSHKey::generate(KEY_ED25519, 256);

  ASSERT_OK(RequestUserAuthService());
  auto [authReq, clientMsg] = BuildUserAuthMessages(*clientKey);

  ExpectHandlePomeriumGrpcAuthRequestNormal(clientMsg);
  ExpectDecodingSuccess();
  ExpectUpstreamConnectMsg();

  ASSERT_OK(WriteMsg(std::move(authReq)));

  // Pomerium can send a ChannelControl message to manually end the stream
  ServerMessage msg;
  *msg.mutable_stream_control()->mutable_close_stream()->mutable_reason() = "test";
  EXPECT_CALL(manage_stream_stream_, closeStream);
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("test"));
  manage_stream_callbacks_->onReceiveMessage(std::make_unique<ServerMessage>(msg));
  mock_connection_.dispatcher_.clearDeferredDeleteList(); // invoke the deferredRun callback
  wire::DisconnectMsg serverDisconnect;
  ASSERT_OK(ReadMsg(serverDisconnect));
  EXPECT_EQ("Cancelled: test", serverDisconnect.description);
}

TEST_F(ServerTransportTest, InvalidStreamControlMessages) {
  ServerMessage msg;
  msg.mutable_auth_response();
  EXPECT_THROW_WITH_MESSAGE(transport_.handleMessage(std::make_unique<ServerMessage>(msg)).IgnoreError(),
                            EnvoyException,
                            "unknown message case");

  ServerMessage msg2;
  msg2.mutable_stream_control();
  EXPECT_THROW_WITH_MESSAGE(transport_.handleMessage(std::make_unique<ServerMessage>(msg2)).IgnoreError(),
                            EnvoyException,
                            "unknown action case");
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
    ExpectUpstreamConnectMsg();

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
        EXPECT_EQ(err, actual);
      });
  } else {
    msg.visit(
      [this](wire::ChannelMsg auto const&) {
        EXPECT_CALL(server_codec_callbacks_, onDecodingSuccess(_)); // common frame overload
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
                           {wire::KexInitMsg{}, "no common algorithm for key exchange; client offered: []; server offered: [\"curve25519-sha256\", \"curve25519-sha256@libssh.org\"]"sv},

                           {wire::ServiceAcceptMsg{}, "unexpected message received: ServiceAccept (6)"sv},
                           {wire::NewKeysMsg{}, "unexpected message received: NewKeys (21)"sv},
                           {wire::UserAuthRequestMsg{}, "unexpected message received: UserAuthRequest (50)"sv},
                           {wire::UserAuthFailureMsg{}, "unexpected message received: UserAuthFailure (51)"sv},
                           {wire::UserAuthSuccessMsg{}, "unexpected message received: UserAuthSuccess (52)"sv},
                           {wire::UserAuthBannerMsg{}, "unexpected message received: UserAuthBanner (53)"sv},
                           {wire::ChannelOpenMsg{}, ""sv},
                           {wire::ChannelOpenConfirmationMsg{}, "unexpected message received: ChannelOpenConfirmation (91)"sv},
                           {wire::ChannelOpenFailureMsg{}, "unexpected message received: ChannelOpenFailure (92)"sv},
                           {wire::ChannelWindowAdjustMsg{}, ""sv},
                           {wire::ChannelDataMsg{}, ""sv},
                           {wire::ChannelExtendedDataMsg{}, ""sv},
                           {wire::ChannelEOFMsg{}, ""sv},
                           {wire::ChannelCloseMsg{}, ""sv},
                           {wire::ChannelRequestMsg{}, ""sv},
                           {wire::ChannelSuccessMsg{}, ""sv},
                           {wire::ChannelFailureMsg{}, ""sv},
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
  ExpectUpstreamConnectMsg();
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
  ExpectUpstreamConnectMsg();
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
  ExpectUpstreamConnectMsg();
  ASSERT_OK(WriteMsg(std::move(authReq)));

  // cheat: this is normally set by upstream user auth service
  transport_.authState().upstream_ext_info = serverExtInfo;

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
  ExpectServeChannelStart();

  ChannelMessage metadataReq;
  (*metadataReq.mutable_metadata()->mutable_filter_metadata())["foo"] = ProtobufWkt::Struct{};
  ExpectSendOnServeChannelStream(metadataReq);

  ASSERT_OK(WriteMsg(std::move(authReq)));
  wire::UserAuthSuccessMsg success;
  ASSERT_OK(ReadMsg(success));

  ExpectUpstreamConnectMsg();

  ChannelMessage ctrl;
  SSHChannelControlAction action;
  auto* allow = action.mutable_hand_off()->mutable_upstream_auth();
  allow->set_username("test");
  auto* upstream = allow->mutable_upstream();
  *upstream->mutable_hostname() = "example";
  *upstream->add_allowed_methods()->mutable_method() = "publickey";
  ctrl.mutable_channel_control()->mutable_control_action()->PackFrom(action);
  EXPECT_CALL(mock_connection_, readDisable(true));
  EXPECT_CALL(serve_channel_stream_, resetStream);
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
                                        public testing::WithParamInterface<std::tuple<std::string_view, uint32_t>> {
};

TEST_P(ServerTransportResponseCodeTest, Respond) {
  auto [msg, expectedCode] = GetParam();
  auto authState = std::make_shared<AuthState>();
  authState->stream_id = 1234;
  SSHRequestHeaderFrame mockHeaderFrame(authState);
  auto status = absl::Status(absl::StatusCode::kInternal, msg);
  auto responseFrame = transport_.respond(status, "", mockHeaderFrame);
  ASSERT_EQ(ResponseHeader | EffectiveCommon | Error,
            responseFrame->frameFlags().frameTags());
  ASSERT_EQ(1234, responseFrame->frameFlags().streamId());
  ASSERT_TRUE(responseFrame->frameFlags().endStream()); // required by generic proxy
  // drainClose is optional, but we always enable it since it closes the connection using
  // Network::ConnectionCloseType::FlushWrite
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
  auto authState = std::make_shared<AuthState>();
  authState->stream_id = 1234;
  SSHRequestHeaderFrame mockHeaderFrame(authState);
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
    .client_version = "SSH-2.0-TestClient\r\n"_bytes,
    .server_version = "SSH-2.0-Envoy\r\n"_bytes,
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

TEST_F(ServerTransportTest, NoopMethods) {
  // these do nothing
  transport_.onAboveWriteBufferHighWatermark();
  transport_.onBelowWriteBufferLowWatermark();
#ifndef SSH_EXPERIMENTAL
  transport_.onEvent({});
#endif
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec