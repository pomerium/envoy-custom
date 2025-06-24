
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h" // IWYU pragma: keep
#include "test/extensions/filters/network/ssh/test_mocks.h"              // IWYU pragma: keep
#include "test/mocks/network/connection.h"
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

MATCHER_P(FrameContainingMsg, msg, "") {
  if constexpr (std::is_same_v<arg_type, std::unique_ptr<CommonFrame>>) {
    switch (arg->frameFlags().frameTags() & FrameTags::FrameTypeMask) {
    case FrameTags::ResponseCommon: {
      const auto& actual = static_cast<const SSHResponseCommonFrame&>(*arg).message();
      if (msg == actual) {
        return true;
      }
      *result_listener << actual;
      return false;
    } break;
    case FrameTags::RequestCommon: {
      const auto& actual = static_cast<const SSHRequestCommonFrame&>(*arg).message();
      if (msg == actual) {
        return true;
      }
      *result_listener << actual;
      return false;
    } break;
    default:
      PANIC("unreachable");
    }
  } else if constexpr (std::is_same_v<arg_type, std::unique_ptr<ResponseHeaderFrame>>) {
    switch (arg->frameFlags().frameTags() & FrameTags::FrameTypeMask) {
    case FrameTags::ResponseHeader: {
      const auto& actual = static_cast<const SSHResponseHeaderFrame&>(*arg).message();
      if (msg == actual) {
        return true;
      }
      *result_listener << actual;
      return false;
    } break;
    default:
      PANIC("unreachable");
    }
  } else {
    static_assert(false, "invalid arg type");
  }
}

MATCHER(SentinelFrame, "") {
  return arg->frameFlags().frameTags() & (EffectiveHeader | Sentinel);
}

class ClientTransportTest : public testing::Test {
public:
  ClientTransportTest()
      : api_(Api::createApiForTest()),
        server_host_key_(*openssh::SSHKey::generate(KEY_ED25519, 256)),
        transport_(*api_, initConfig()) {
  }

  const wire::KexInitMsg kex_init_ = {
    .cookie = {{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
    .kex_algorithms = {{"curve25519-sha256"s, "ext-info-s"s, "kex-strict-s-v00@openssh.com"s}},
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

  void SetUp() override {
    transport_.setCodecCallbacks(client_codec_callbacks_);
    ON_CALL(client_codec_callbacks_, writeToConnection(_))
      .WillByDefault([this](Envoy::Buffer::Instance& buffer) {
        output_buffer_.move(buffer);
      });
    EXPECT_CALL(client_codec_callbacks_, writeToConnection(_))
      .Times(AnyNumber());
    ON_CALL(client_codec_callbacks_, connection())
      .WillByDefault(Return(makeOptRef<Network::Connection>(mock_connection_)));
    EXPECT_CALL(client_codec_callbacks_, connection())
      .Times(AnyNumber());
  }

  void StartTransportNormal() {
    // start the client transport by simulating a SSHRequestHeaderFrame forwarded from the
    // server transport
    auto authState = std::make_shared<AuthState>();
    authState->server_version = "SSH-2.0-Envoy";
    authState->channel_mode = ChannelMode::Normal;
    authState->allow_response = std::make_unique<AllowResponse>();
    authState->allow_response->set_username("foo");
    authState->allow_response->mutable_upstream()->set_hostname("example");
    *authState->allow_response->mutable_upstream()->add_allowed_methods()->mutable_method() = "publickey";
    GenericProxy::MockEncodingContext ctx;
    SSHRequestHeaderFrame reqHeaderFrame(authState);
    ASSERT_OK(transport_.encode(reqHeaderFrame, ctx).status());
    DoKeyExchange();
  }

  AuthStateSharedPtr BuildHandoffAuthState() {
    auto authState = std::make_shared<AuthState>();
    authState->server_version = "SSH-2.0-Envoy";
    authState->channel_mode = ChannelMode::Handoff;
    authState->handoff_info.handoff_in_progress = true;
    authState->handoff_info.channel_info = std::make_unique<SSHDownstreamChannelInfo>();
    authState->handoff_info.channel_info->set_downstream_channel_id(100);
    authState->handoff_info.channel_info->set_channel_type("session");
    authState->handoff_info.channel_info->set_internal_upstream_channel_id(200);
    authState->handoff_info.channel_info->set_initial_window_size(64 * wire::MaxPacketSize);
    authState->handoff_info.channel_info->set_max_packet_size(wire::MaxPacketSize);
    authState->handoff_info.pty_info = std::make_unique<SSHDownstreamPTYInfo>();
    authState->handoff_info.pty_info->set_term_env("xterm-256color");
    authState->handoff_info.pty_info->set_width_columns(80);
    authState->handoff_info.pty_info->set_height_rows(24);
    authState->handoff_info.pty_info->set_width_px(300);
    authState->handoff_info.pty_info->set_height_px(250);
    authState->allow_response = std::make_unique<AllowResponse>();
    authState->allow_response->set_username("foo");
    authState->allow_response->mutable_upstream()->set_hostname("example");
    *authState->allow_response->mutable_upstream()->add_allowed_methods()->mutable_method() = "publickey";
    return authState;
  }

  void StartTransportHandoff() {
    GenericProxy::MockEncodingContext ctx;
    SSHRequestHeaderFrame reqHeaderFrame(BuildHandoffAuthState());
    ASSERT_OK(transport_.encode(reqHeaderFrame, ctx).status());
    DoKeyExchange();
  }

  void StartTransportDirectTcpip() {
    GenericProxy::MockEncodingContext ctx;
    auto state = BuildHandoffAuthState();
    state->handoff_info.channel_info->set_channel_type("direct-tcpip");
    state->allow_response->mutable_upstream()->set_direct_tcpip(true);
    SSHRequestHeaderFrame reqHeaderFrame(state);
    wire::ChannelOpenConfirmationMsg expectedMsg;
    expectedMsg.recipient_channel = 100;
    expectedMsg.sender_channel = 200;
    expectedMsg.initial_window_size = 64 * wire::MaxPacketSize;
    expectedMsg.max_packet_size = wire::MaxPacketSize;
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{expectedMsg}), _));
    auto r = transport_.encode(reqHeaderFrame, ctx);
    ASSERT_OK(r.status());
    ASSERT_EQ(0, *r); // nothing sent to the upstream
  }

  void DoKeyExchange() {
    // perform version exchange
    input_buffer_.add("SSH-2.0-TestServer\r\n");
    EXPECT_TRUE(output_buffer_.startsWith("SSH-2.0-Envoy\r\n"));
    output_buffer_.drain(15);
    transport_.decode(input_buffer_, false);

    // perform manual key exchange as the server
    wire::KexInitMsg clientKexInit;
    ASSERT_OK(wire::decodePacket(output_buffer_, clientKexInit).status());
    ASSERT_OK(wire::encodePacket(input_buffer_, kex_init_, 8, 0).status());
    transport_.decode(input_buffer_, false);
    HandshakeMagics magics{
      .client_version = "SSH-2.0-Envoy"_bytes,
      .server_version = "SSH-2.0-TestServer"_bytes,
      .client_kex_init = *wire::encodeTo<bytes>(clientKexInit),
      .server_kex_init = *wire::encodeTo<bytes>(kex_init_),
    };

    DirectionalPacketCipherFactoryRegistry reg;
    reg.registerType<Chacha20Poly1305CipherFactory>();
    Curve25519Sha256KexAlgorithmFactory f;
    auto kexAlg = f.create(&magics, &kex_algs_, server_host_key_.get());
    wire::Message clientEcdhInit;
    ASSERT_OK(wire::decodePacket(output_buffer_, clientEcdhInit).status());
    auto r = kexAlg->handleServerRecv(clientEcdhInit);
    ASSERT_OK(r.status());
    ASSERT_TRUE(r->has_value());
    (**r)->session_id = (**r)->exchange_hash; // this needs to be set manually
    current_session_id_ = (**r)->session_id;

    server_cipher_ = makePacketCipherFromKexResult<ServerCodec>(reg, (*r)->get());
    ASSERT_NE(nullptr, server_cipher_);

    ASSERT_OK(wire::encodePacket(input_buffer_, kexAlg->buildServerReply(***r), 8, 0).status());
    ASSERT_OK(wire::encodePacket(input_buffer_, wire::NewKeysMsg{}, 8, 0).status());
    transport_.decode(input_buffer_, false);

    wire::NewKeysMsg clientNewKeys;
    ASSERT_OK(wire::decodePacket(output_buffer_, clientNewKeys).status());
  }

  absl::Status WriteMsg(wire::Message&& msg) {
    Buffer::OwnedImpl buf;
    if (auto n = wire::encodePacket(buf, msg,
                                    server_cipher_->blockSize(openssh::CipherMode::Write),
                                    server_cipher_->aadSize(openssh::CipherMode::Write));
        !n.ok()) {
      return n.status();
    }
    if (auto stat = server_cipher_->encryptPacket(write_seqnum_++, input_buffer_, buf); !stat.ok()) {
      return stat;
    }
    transport_.decode(input_buffer_, false);
    return absl::OkStatus();
  }

  absl::Status ReadMsg(auto& msg) {
    Buffer::OwnedImpl buf;
    if (auto n = server_cipher_->decryptPacket(read_seqnum_++, buf, output_buffer_); !n.ok()) {
      return n.status();
    }
    return wire::decodePacket(buf, msg).status();
  }

  absl::Status WriteFromDownstream(wire::Message&& msg) {
    GenericProxy::MockEncodingContext ctx;

    SSHRequestCommonFrame frame(std::move(msg));
    return transport_.encode(frame, ctx).status();
  }

  absl::Status ExchangeExtInfo() {
    wire::ExtInfoMsg clientExtInfo;
    RETURN_IF_NOT_OK(ReadMsg(clientExtInfo));
    EXPECT_TRUE(clientExtInfo.hasExtension<wire::PingExtension>());

    wire::ExtInfoMsg serverExtInfo;
    serverExtInfo.extensions->emplace_back(wire::PingExtension{.version = "0"s});
    serverExtInfo.extensions->emplace_back(wire::ExtInfoInAuthExtension{.version = "0"s});
    RETURN_IF_NOT_OK(WriteMsg(wire::Message{serverExtInfo}));
    EXPECT_EQ(serverExtInfo, transport_.peerExtInfo());
    return absl::OkStatus();
  }

  absl::Status HandleUserAuth() {
    wire::ServiceRequestMsg clientUserAuthServiceRequest;
    EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
    EXPECT_EQ("ssh-userauth", clientUserAuthServiceRequest.service_name);

    EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

    wire::UserAuthRequestMsg clientUserAuthRequest;
    EXPECT_OK(ReadMsg(clientUserAuthRequest));
    EXPECT_EQ("foo", clientUserAuthRequest.username); // from downstream auth state
    EXPECT_EQ("ssh-connection", clientUserAuthRequest.service_name);
    if (!clientUserAuthRequest.request.has_value()) {
      return absl::InternalError("test failure: request has no value");
    }
    clientUserAuthRequest.request.visit(
      [this](wire::PubKeyUserAuthRequestMsg& pub_key_req) {
        EXPECT_TRUE(pub_key_req.has_signature);
        EXPECT_FALSE(pub_key_req.signature->empty());
        EXPECT_FALSE(pub_key_req.public_key->empty());

        auto pk = openssh::SSHKey::fromPublicKeyBlob(pub_key_req.public_key);
        EXPECT_OK(pk.status());
        EXPECT_TRUE(openssh::SSHKey::keyTypeIsCert(pk.value()->keyType()));

        ExpectDecodingSuccess(FrameContainingMsg(wire::Message{wire::UserAuthSuccessMsg{}}));
        EXPECT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));
      },
      [](auto&) {
        ADD_FAILURE() << "[test error] unexpected request type, expected PubKeyUserAuthRequestMsg";
      });
    return HasFailure()
             ? absl::InternalError("test failed")
             : absl::OkStatus();
  }

  absl::Status DoRekey() {
    [this] {
      ASSERT_EQ(0, input_buffer_.length());
      ASSERT_EQ(0, output_buffer_.length());

      ASSERT_OK(WriteMsg(auto(kex_init_)));

      wire::KexInitMsg clientKexInit;
      ASSERT_OK(ReadMsg(clientKexInit));
      HandshakeMagics magics{
        .client_version = "SSH-2.0-Envoy"_bytes,
        .server_version = "SSH-2.0-TestServer"_bytes,
        .client_kex_init = *wire::encodeTo<bytes>(clientKexInit),
        .server_kex_init = *wire::encodeTo<bytes>(kex_init_),
      };
      DirectionalPacketCipherFactoryRegistry reg;
      reg.registerType<Chacha20Poly1305CipherFactory>();
      Curve25519Sha256KexAlgorithmFactory f;
      auto kexAlg = f.create(&magics, &kex_algs_, server_host_key_.get());
      wire::Message clientEcdhInit;
      ASSERT_OK(ReadMsg(clientEcdhInit));
      auto r = kexAlg->handleServerRecv(clientEcdhInit);
      ASSERT_OK(r.status());
      ASSERT_TRUE(r->has_value());
      (**r)->session_id = *current_session_id_;
      ASSERT_OK(WriteMsg(kexAlg->buildServerReply(***r)));
      ASSERT_OK(WriteMsg(wire::NewKeysMsg{}));
      write_seqnum_ = 0;
      wire::NewKeysMsg clientNewKeys;
      ASSERT_OK(ReadMsg(clientNewKeys));
      read_seqnum_ = 0;
      ASSERT_EQ(0, input_buffer_.length()); // there should be no ExtInfo sent

      server_cipher_ = makePacketCipherFromKexResult<ServerCodec>(reg, (**r).get());
    }();
    return HasFailure()
             ? absl::InternalError("test failed")
             : absl::OkStatus();
  }

  void ExpectDecodingSuccess(auto matcher) {
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(matcher, _)) // header frame overload
      .WillOnce(Invoke([this](ResponseHeaderFramePtr frame, absl::optional<StartTime>) {
        ASSERT_EQ(transport_.streamId(), frame->frameFlags().streamId());
        ASSERT_EQ(0, frame->frameFlags().rawFlags());
        ASSERT_EQ(FrameTags::ResponseHeader | FrameTags::EffectiveHeader, frame->frameFlags().frameTags());
      }));
  }

  void ExpectDisconnectAsHeader(absl::Status status) {
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{
                                                             wire::DisconnectMsg{
                                                               .reason_code = openssh::statusCodeToDisconnectCode(status.code()),
                                                               .description = statusToString(status),
                                                             },
                                                           }),
                                                           _));
  }

  void ExpectDisconnectAsHeader(wire::DisconnectMsg msg) {
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{msg}), _));
  }

  seqnum_t read_seqnum_{};
  seqnum_t write_seqnum_{};
  std::optional<bytes> current_session_id_;
  std::unique_ptr<PacketCipher> server_cipher_;
  Envoy::Buffer::OwnedImpl input_buffer_;
  Envoy::Buffer::OwnedImpl output_buffer_;
  Api::ApiPtr api_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  openssh::SSHKeyPtr server_host_key_;
  testing::NiceMock<Envoy::Network::MockServerConnection> mock_connection_;
  testing::StrictMock<MockClientCodecCallbacks> client_codec_callbacks_;

  SshClientTransport transport_;

private:
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig>& initConfig() {
    config_ = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
    for (auto keyName : {"rsa_1", "ed25519_1"}) {
      auto hostKeyFile = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
      config_->add_host_keys()->set_filename(hostKeyFile);
    }
    auto userCaKeyFile = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_2", 0600);
    config_->mutable_user_ca_key()->set_filename(userCaKeyFile);
    return config_;
  }
};
// NOLINTEND(readability-identifier-naming)

TEST_F(ClientTransportTest, ExchangeExtInfo) {
  StartTransportNormal();

  ASSERT_OK(ExchangeExtInfo());
}

TEST_F(ClientTransportTest, UserAuthServiceRequest) {
  StartTransportNormal();

  ASSERT_OK(ExchangeExtInfo());
  ASSERT_OK(HandleUserAuth());
}

TEST_F(ClientTransportTest, OpenChannelFromDownstream) {
  StartTransportNormal();

  ASSERT_OK(ExchangeExtInfo());
  ASSERT_OK(HandleUserAuth());

  for (int i = 0; i < 10; i++) {
    wire::ChannelOpenMsg send;
    send.channel_type = "session"s;
    send.sender_channel = (1 + i);
    send.initial_window_size = 64 * wire::MaxPacketSize;
    send.max_packet_size = wire::MaxPacketSize;

    ASSERT_OK(WriteFromDownstream(wire::Message{send}));

    wire::ChannelOpenMsg recv;
    ASSERT_OK(ReadMsg(recv));
    EXPECT_EQ(send, recv);

    wire::ChannelOpenConfirmationMsg confirm;
    confirm.recipient_channel = recv.sender_channel;
    confirm.sender_channel = (100 + i);
    confirm.initial_window_size = 64 * wire::MaxPacketSize;
    confirm.max_packet_size = wire::MaxPacketSize;
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{confirm})));
    ASSERT_OK(WriteMsg(wire::Message{confirm}));
  }

  for (int i = 0; i < 10; i++) {
    wire::ChannelDataMsg data;
    data.recipient_channel = (1 + i);
    data.data = to_bytes(fmt::format("hello channel {}", 1 + i));
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{data})));
    ASSERT_OK(WriteMsg(wire::Message{data}));
  }
}

TEST_F(ClientTransportTest, ForwardGlobalRequestToDownstream) {
  StartTransportNormal();

  ASSERT_OK(ExchangeExtInfo());
  ASSERT_OK(HandleUserAuth());

  wire::GlobalRequestMsg upstreamReq;
  upstreamReq.request = wire::HostKeysProveRequestMsg{}; // can be any message the client transport ignores
  EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{upstreamReq})));
  ASSERT_OK(WriteMsg(wire::Message{upstreamReq}));
}

TEST_F(ClientTransportTest, HandleHostKeysMsgGlobalRequest) {
  StartTransportNormal();

  ASSERT_OK(ExchangeExtInfo());
  ASSERT_OK(HandleUserAuth());

  wire::GlobalRequestMsg upstreamReq;
  upstreamReq.request = wire::HostKeysMsg{};
  ASSERT_OK(WriteMsg(wire::Message{upstreamReq}));
}

TEST_F(ClientTransportTest, HandleInvalidServiceAccept) {
  StartTransportNormal();

  ASSERT_OK(ExchangeExtInfo());
  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_EQ("ssh-userauth", clientUserAuthServiceRequest.service_name);

  // errors are forwarded to the downstream as disconnect messages, which invokes the server
  // transport's respond method
  ExpectDisconnectAsHeader(absl::InvalidArgumentError("received ServiceAccept message for unknown service not-ssh-userauth"));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "not-ssh-userauth"s}}));
}

TEST_F(ClientTransportTest, HandleIgnoredMessages) {
  StartTransportNormal();
  ASSERT_OK(ExchangeExtInfo());

  // These messages should be logged and ignored
  ASSERT_OK(WriteMsg(wire::Message{wire::IgnoreMsg{}}));
  ASSERT_OK(WriteMsg(wire::Message{wire::DebugMsg{}}));
  ASSERT_OK(WriteMsg(wire::Message{wire::UnimplementedMsg{}}));
}

TEST_F(ClientTransportTest, HandleUpstreamDisconnect) {
  StartTransportNormal();
  ASSERT_OK(ExchangeExtInfo());

  wire::DisconnectMsg dc{
    .reason_code = SSH2_DISCONNECT_PROTOCOL_ERROR,
    .description = "test"s,
  };
  ExpectDisconnectAsHeader(dc);
  ASSERT_OK(WriteMsg(wire::Message{dc}));
}

TEST_F(ClientTransportTest, HandleInvalidMessage) {
  ASSERT_EQ(absl::InternalError("received invalid message: KexInit (20)"),
            transport_.handleMessage(wire::Message{wire::KexInitMsg{}}));
}

TEST_F(ClientTransportTest, Handoff) {
  StartTransportHandoff();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_EQ("ssh-userauth", clientUserAuthServiceRequest.service_name);

  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  EXPECT_EQ("foo", clientUserAuthRequest.username); // from downstream auth state
  EXPECT_EQ("ssh-connection", clientUserAuthRequest.service_name);
  ASSERT_TRUE(clientUserAuthRequest.request.has_value());
  clientUserAuthRequest.request.visit(
    [](wire::PubKeyUserAuthRequestMsg&) {},
    [](auto&) { FAIL() << "unexpected message type received"; });

  // upon successful user auth, the client will open a channel matching the downstream's channel
  ASSERT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  {
    wire::ChannelOpenMsg req;
    ASSERT_OK(ReadMsg(req));
    ASSERT_EQ("session", *req.channel_type);
    ASSERT_EQ(100, *req.sender_channel);
    ASSERT_EQ(64 * wire::MaxPacketSize, *req.initial_window_size);
    ASSERT_EQ(wire::MaxPacketSize, *req.max_packet_size);

    ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = 100,
      .sender_channel = 300,
      .initial_window_size = 64 * wire::MaxPacketSize,
      .max_packet_size = wire::MaxPacketSize,
    }));
  }

  // send a message the client should ignore
  ASSERT_OK(WriteMsg(wire::DebugMsg{}));

  // next, the client will open a pty
  {
    wire::ChannelRequestMsg cr;
    ASSERT_OK(ReadMsg(cr));
    ASSERT_EQ(300, *cr.recipient_channel);
    ASSERT_TRUE(cr.want_reply);
    ASSERT_TRUE(cr.request.has_value());
    cr.request.visit(
      [](wire::PtyReqChannelRequestMsg& pty_req) {
        ASSERT_EQ("xterm-256color", *pty_req.term_env);
        ASSERT_EQ(80, *pty_req.width_columns);
        ASSERT_EQ(24, *pty_req.height_rows);
        ASSERT_EQ(300, *pty_req.width_px);
        ASSERT_EQ(250, *pty_req.height_px);
      },
      [](auto&) {
        FAIL() << "unexpected message";
      });
  }

  ASSERT_FALSE(HasFailure());

  // last, the client will open a shell, and signal to the server transport that the handoff is done
  EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(
                                         AllOf(FrameContainingMsg(wire::Message{wire::IgnoreMsg{}}),
                                               SentinelFrame()),
                                         _))
    .WillOnce([this] {
      // the server transport updates handoff_in_progress when it receives the sentinel message
      transport_.authState().handoff_info.handoff_in_progress = false;
    });

  ASSERT_OK(WriteMsg(wire::ChannelSuccessMsg{
    .recipient_channel = 100,
  }));

  {
    wire::ChannelRequestMsg cr;
    ASSERT_OK(ReadMsg(cr));
    ASSERT_EQ(300, *cr.recipient_channel);
    ASSERT_FALSE(cr.want_reply);
    ASSERT_TRUE(cr.request.has_value());
    cr.request.visit(
      [](wire::ShellChannelRequestMsg&) {},
      [](auto&) {
        FAIL() << "unexpected message";
      });
  }

  // Post-handoff, we should be able to forward messages in both directions, with channel id remapping
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelDataMsg{
      .recipient_channel = 200,
      .data = "foo"_bytes,
    }));
    wire::ChannelDataMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
    ASSERT_EQ("foo"_bytes, *msg.data);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelSuccessMsg{
      .recipient_channel = 200,
    }));
    wire::ChannelSuccessMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelFailureMsg{
      .recipient_channel = 200,
    }));
    wire::ChannelFailureMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = 200,
    }));
    wire::ChannelOpenConfirmationMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelOpenFailureMsg{
      .recipient_channel = 200,
    }));
    wire::ChannelOpenFailureMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::DebugMsg{}));
    wire::DebugMsg msg;
    ASSERT_OK(ReadMsg(msg));
  }

  {
    wire::ChannelDataMsg toDownstream{
      .recipient_channel = 100,
      .data = "bar"_bytes,
    };
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{toDownstream}));
  }

  {
    wire::ChannelSuccessMsg toDownstream{.recipient_channel = 100};
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{toDownstream}));
  }

  {
    wire::ChannelFailureMsg toDownstream{.recipient_channel = 100};
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{toDownstream}));
  }

  {
    wire::ChannelOpenConfirmationMsg toDownstream{.recipient_channel = 100};
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{toDownstream}));
  }

  {
    wire::ChannelOpenFailureMsg toDownstream{.recipient_channel = 100};
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{toDownstream}));
  }

  // the client still drops these messages
  ASSERT_OK(WriteMsg(wire::Message{wire::IgnoreMsg{}}));
  ASSERT_OK(WriteMsg(wire::Message{wire::DebugMsg{}}));
  ASSERT_OK(WriteMsg(wire::Message{wire::UnimplementedMsg{}}));
}

TEST_F(ClientTransportTest, Handoff_UserAuthFailure) {
  StartTransportHandoff();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  ASSERT_TRUE(clientUserAuthRequest.request.has_value());
  clientUserAuthRequest.request.visit(
    [](wire::PubKeyUserAuthRequestMsg&) {},
    [](auto&) { FAIL() << "unexpected message type received"; });

  ExpectDisconnectAsHeader(absl::PermissionDeniedError(""));
  ASSERT_OK(WriteMsg(wire::UserAuthFailureMsg{}));
}

TEST_F(ClientTransportTest, Handoff_SendPtyRequestFailure) {
  auto authState = BuildHandoffAuthState();
  authState->handoff_info.pty_info->mutable_term_env()->resize(wire::MaxPacketSize);

  GenericProxy::MockEncodingContext ctx;
  SSHRequestHeaderFrame reqHeaderFrame(authState);
  ASSERT_OK(transport_.encode(reqHeaderFrame, ctx).status());
  DoKeyExchange();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  ASSERT_TRUE(clientUserAuthRequest.request.has_value());
  clientUserAuthRequest.request.visit(
    [](wire::PubKeyUserAuthRequestMsg&) {},
    [](auto&) { FAIL() << "unexpected message type received"; });

  ASSERT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  wire::ChannelOpenMsg req;
  ASSERT_OK(ReadMsg(req));

  ExpectDisconnectAsHeader(absl::AbortedError("error requesting pty: error encoding packet: message size too large"));
  ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = 100,
    .sender_channel = 300,
    .initial_window_size = 64 * wire::MaxPacketSize,
    .max_packet_size = wire::MaxPacketSize,
  }));
}

TEST_F(ClientTransportTest, Handoff_NoDownstreamPty) {
  GenericProxy::MockEncodingContext ctx;
  auto authState = BuildHandoffAuthState();
  authState->handoff_info.pty_info = nullptr;
  SSHRequestHeaderFrame reqHeaderFrame(authState);
  ASSERT_OK(transport_.encode(reqHeaderFrame, ctx).status());
  DoKeyExchange();

  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  ASSERT_TRUE(clientUserAuthRequest.request.has_value());
  clientUserAuthRequest.request.visit(
    [](wire::PubKeyUserAuthRequestMsg&) {},
    [](auto&) { FAIL() << "unexpected message type received"; });

  ASSERT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  wire::ChannelOpenMsg req;
  ASSERT_OK(ReadMsg(req));
  ExpectDisconnectAsHeader(absl::InvalidArgumentError("session is not interactive"));
  ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = 100,
    .sender_channel = 300,
    .initial_window_size = 64 * wire::MaxPacketSize,
    .max_packet_size = wire::MaxPacketSize,
  }));
}

TEST_F(ClientTransportTest, Handoff_ChannelOpenFailure) {
  StartTransportHandoff();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  ASSERT_TRUE(clientUserAuthRequest.request.has_value());
  clientUserAuthRequest.request.visit(
    [](wire::PubKeyUserAuthRequestMsg&) {},
    [](auto&) { FAIL() << "unexpected message type received"; });

  ASSERT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  wire::ChannelOpenMsg req;
  ASSERT_OK(ReadMsg(req));
  ExpectDisconnectAsHeader(absl::UnavailableError("test error"));
  ASSERT_OK(WriteMsg(wire::ChannelOpenFailureMsg{
    .recipient_channel = 100,
    .description = "test error"s,
  }));
}

TEST_F(ClientTransportTest, Handoff_PtyOpenFailure) {
  StartTransportHandoff();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  ASSERT_TRUE(clientUserAuthRequest.request.has_value());
  clientUserAuthRequest.request.visit(
    [](wire::PubKeyUserAuthRequestMsg&) {},
    [](auto&) { FAIL() << "unexpected message type received"; });

  ASSERT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  wire::ChannelOpenMsg req;
  ASSERT_OK(ReadMsg(req));
  ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = 100,
    .sender_channel = 300,
    .initial_window_size = 64 * wire::MaxPacketSize,
    .max_packet_size = wire::MaxPacketSize,
  }));

  wire::ChannelRequestMsg cr;
  ASSERT_OK(ReadMsg(cr));

  ExpectDisconnectAsHeader(absl::InternalError("failed to open upstream tty"));
  ASSERT_OK(WriteMsg(wire::ChannelFailureMsg{
    .recipient_channel = 100,
  }));
}

class ClientTransportLoadHostKeysTest : public ClientTransportTest {
public:
  void SetUp() override {}
};

TEST_F(ClientTransportLoadHostKeysTest, LoadHostKeysError) {
  for (auto hostKey : config_->host_keys()) {
    ASSERT_TRUE(hostKey.has_filename()); // sanity check
    chmod(hostKey.filename().c_str(), 0644);
  }
  EXPECT_THROW_WITH_MESSAGE(transport_.setCodecCallbacks(client_codec_callbacks_),
                            EnvoyException,
                            "Invalid Argument: bad permissions");
}

TEST_F(ClientTransportTest, EncodeInvalidFrameType) {
  GenericProxy::MockEncodingContext ctx;

  SSHResponseHeaderFrame frame{wire::IgnoreMsg{}, {}};
  EXPECT_THROW_WITH_MESSAGE(
    transport_.encode(frame, ctx).IgnoreError(),
    EnvoyException,
    "bug: unknown frame kind");
}

TEST_F(ClientTransportTest, HandleRekey) {
  StartTransportNormal();
  ASSERT_OK(ExchangeExtInfo());
  ASSERT_OK(HandleUserAuth());

  ASSERT_OK(DoRekey());

  wire::PingMsg ping{.data = "test"s};
  EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{ping})));
  ASSERT_OK(WriteMsg(wire::Message{ping}));
}

TEST_F(ClientTransportTest, HandleRekeyDuringHandoff) {
  StartTransportHandoff();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));

  ASSERT_OK(DoRekey());

  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  EXPECT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  wire::ChannelOpenMsg req;
  ASSERT_OK(ReadMsg(req));

  ASSERT_OK(DoRekey());

  ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = 100,
    .sender_channel = 300,
    .initial_window_size = 64 * wire::MaxPacketSize,
    .max_packet_size = wire::MaxPacketSize,
  }));

  wire::ChannelRequestMsg ptyChannelRequest;
  ASSERT_OK(ReadMsg(ptyChannelRequest));
  ptyChannelRequest.request.visit(
    [](wire::PtyReqChannelRequestMsg&) {},
    [](auto&) {
      FAIL() << "unexpected message";
    });

  ASSERT_FALSE(HasFailure());

  ASSERT_OK(DoRekey());

  EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(
                                         AllOf(FrameContainingMsg(wire::Message{wire::IgnoreMsg{}}),
                                               SentinelFrame()),
                                         _))
    .WillOnce([this] {
      transport_.authState().handoff_info.handoff_in_progress = false;
    });

  ASSERT_OK(WriteMsg(wire::ChannelSuccessMsg{.recipient_channel = 100}));

  wire::ChannelRequestMsg shellChannelRequest;
  ASSERT_OK(ReadMsg(shellChannelRequest));
  shellChannelRequest.request.visit(
    [](wire::ShellChannelRequestMsg&) {},
    [](auto&) {
      FAIL() << "unexpected message";
    });
}

TEST_F(ClientTransportTest, HandleRekeyAfterHandoff) {
  StartTransportHandoff();
  ASSERT_OK(ExchangeExtInfo());

  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));

  wire::UserAuthRequestMsg clientUserAuthRequest;
  EXPECT_OK(ReadMsg(clientUserAuthRequest));
  EXPECT_OK(WriteMsg(wire::UserAuthSuccessMsg{}));

  wire::ChannelOpenMsg req;
  ASSERT_OK(ReadMsg(req));

  ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
    .recipient_channel = 100,
    .sender_channel = 300,
    .initial_window_size = 64 * wire::MaxPacketSize,
    .max_packet_size = wire::MaxPacketSize,
  }));

  wire::ChannelRequestMsg ptyChannelRequest;
  ASSERT_OK(ReadMsg(ptyChannelRequest));
  ptyChannelRequest.request.visit(
    [](wire::PtyReqChannelRequestMsg&) {},
    [](auto&) {
      FAIL() << "unexpected message";
    });

  ASSERT_FALSE(HasFailure());

  EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(
                                         AllOf(FrameContainingMsg(wire::Message{wire::IgnoreMsg{}}),
                                               SentinelFrame()),
                                         _))
    .WillOnce([this] {
      transport_.authState().handoff_info.handoff_in_progress = false;
    });

  ASSERT_OK(WriteMsg(wire::ChannelSuccessMsg{.recipient_channel = 100}));

  wire::ChannelRequestMsg shellChannelRequest;
  ASSERT_OK(ReadMsg(shellChannelRequest));
  shellChannelRequest.request.visit(
    [](wire::ShellChannelRequestMsg&) {},
    [](auto&) {
      FAIL() << "unexpected message";
    });
  ASSERT_OK(DoRekey());

  // checking that this is forwarded to the downstream is important - it means we correctly
  // updated the upstream's ext info when intercepting the user auth success message, which
  // enables ping forwarding
  wire::PingMsg ping{.data = "test"s};
  EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{ping})));
  ASSERT_OK(WriteMsg(wire::Message{ping}));
}

TEST_F(ClientTransportTest, DirectTcpipMode) {
  server_cipher_ = std::make_unique<PacketCipher>(std::make_unique<NoCipher>(),
                                                  std::make_unique<NoCipher>());
  StartTransportDirectTcpip();

  // downstream->upstream
  {
    wire::KexInitMsg send{.reserved = 1234};
    Buffer::OwnedImpl packet;
    ASSERT_OK(wire::encodePacket(packet, send, 8, 0).status());
    wire::ChannelDataMsg data{
      .recipient_channel = 200,
      .data = wire::flushTo<bytes>(packet),
    };
    SSHRequestCommonFrame frame(wire::Message{data});
    GenericProxy::MockEncodingContext ctx;
    ASSERT_OK(transport_.encode(frame, ctx).status());

    wire::KexInitMsg recv;
    ASSERT_OK(ReadMsg(recv));
    ASSERT_EQ(1234, *recv.reserved);
  }
  // upstream->downstream
  {
    wire::KexInitMsg send{.reserved = 2345};
    Buffer::OwnedImpl packet;
    // disable random padding so that we can match the expected packet contents exactly
    ASSERT_OK(wire::encodePacket(packet, send, 8, 0, false).status());
    wire::ChannelDataMsg expected{
      .recipient_channel = 100,
      .data = wire::flushTo<bytes>(packet),
    };

    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{expected})));
    Buffer::OwnedImpl buf;
    ASSERT_OK(wire::encodePacket(buf, send,
                                 server_cipher_->blockSize(openssh::CipherMode::Write),
                                 server_cipher_->aadSize(openssh::CipherMode::Write),
                                 false) // disable random padding
                .status());
    ASSERT_OK(server_cipher_->encryptPacket(write_seqnum_++, input_buffer_, buf));
    transport_.decode(input_buffer_, false);
  }

  // send EOF from the downstream
  {
    wire::ChannelEOFMsg eof{.recipient_channel = 200};
    EXPECT_CALL(mock_connection_, close(_));

    SSHRequestCommonFrame frame(wire::Message{eof});
    GenericProxy::MockEncodingContext ctx;
    ASSERT_EQ(absl::CancelledError("EOF"), transport_.encode(frame, ctx).status());
  }
}

TEST_F(ClientTransportTest, DirectTcpipMode_WrongMessageTypeReceived) {
  server_cipher_ = std::make_unique<PacketCipher>(std::make_unique<NoCipher>(),
                                                  std::make_unique<NoCipher>());
  StartTransportDirectTcpip();

  SSHRequestCommonFrame frame(wire::Message{wire::DebugMsg{}});
  GenericProxy::MockEncodingContext ctx;
  ASSERT_EQ(absl::InvalidArgumentError("unexpected message of type Debug (4) on direct-tcpip channel"),
            transport_.encode(frame, ctx).status());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec