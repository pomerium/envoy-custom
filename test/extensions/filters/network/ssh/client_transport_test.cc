
#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h" // IWYU pragma: keep
#include "test/extensions/filters/network/ssh/test_mocks.h"              // IWYU pragma: keep
#include "test/mocks/network/connection.h"
#include "test/mocks/server/server_factory_context.h"
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
      : downstream_filter_state_(StreamInfo::FilterState::LifeSpan::FilterChain),
        server_host_key_(*openssh::SSHKey::generate(KEY_ED25519, 256)),
        transport_(server_factory_context_, initConfig()) {}

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
    // Inject a new channel id manager into the mock filter state. This would normally be created
    // by the server transport
    channel_id_manager_ = std::make_shared<ChannelIDManager>(1000);
    mock_connection_.streamInfo().filterState()->setData(
      ChannelIDManagerFilterStateKey,
      channel_id_manager_,
      StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Connection,
      StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);

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

  void SetDownstreamAuthInfo(AuthInfoSharedPtr info) {
    ASSERT(!downstream_filter_state_.hasDataWithName(AuthInfoFilterStateKey));
    downstream_filter_state_.setData(
      AuthInfoFilterStateKey, info,
      StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Request,
      StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
  }

  void StartTransportNormal() {
    // start the client transport by simulating a SSHRequestHeaderFrame forwarded from the
    // server transport
    auto authInfo = std::make_shared<AuthInfo>();
    authInfo->server_version = "SSH-2.0-Envoy";
    authInfo->channel_mode = ChannelMode::Normal;
    authInfo->allow_response = std::make_unique<AllowResponse>();
    authInfo->allow_response->set_username("foo");
    authInfo->allow_response->mutable_upstream()->set_hostname("example");
    auto* publicKeyMethod = authInfo->allow_response->mutable_upstream()->add_allowed_methods();
    SetDownstreamAuthInfo(authInfo);
    publicKeyMethod->set_method("publickey");
    PublicKeyAllowResponse publicKeyMethodData;
    Permissions permissions;
    permissions.set_permit_port_forwarding(true);
    permissions.set_permit_agent_forwarding(true);
    permissions.set_permit_x11_forwarding(true);
    permissions.set_permit_pty(true);
    permissions.set_permit_user_rc(true);
    *permissions.mutable_valid_start_time() = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(
      absl::ToUnixNanos(absl::Now()));
    *permissions.mutable_valid_end_time() = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(
      absl::ToUnixNanos(absl::Now() + absl::Hours(1)));
    *publicKeyMethodData.mutable_permissions() = std::move(permissions);
    publicKeyMethod->mutable_method_data()->PackFrom(publicKeyMethodData);
    GenericProxy::MockEncodingContext ctx;
    SSHRequestHeaderFrame reqHeaderFrame("example", 0, downstream_filter_state_);
    ASSERT_OK(transport_.encode(reqHeaderFrame, ctx).status());
    DoKeyExchange();
  }

  AuthInfoSharedPtr BuildHandoffAuthInfo() {
    auto internalId = *channel_id_manager_->allocateNewChannel(Peer::Downstream);
    EXPECT_OK(channel_id_manager_->bindChannelID(internalId, PeerLocalID{
                                                               .channel_id = 1,
                                                               .local_peer = Peer::Downstream,
                                                             }));
    auto authInfo = std::make_shared<AuthInfo>();
    authInfo->server_version = "SSH-2.0-Envoy";
    authInfo->channel_mode = ChannelMode::Handoff;
    authInfo->handoff_info.handoff_in_progress = true;
    authInfo->handoff_info.channel_info = std::make_unique<SSHDownstreamChannelInfo>();
    authInfo->handoff_info.channel_info->set_downstream_channel_id(1);
    authInfo->handoff_info.channel_info->set_channel_type("session");
    authInfo->handoff_info.channel_info->set_internal_upstream_channel_id(internalId);
    authInfo->handoff_info.channel_info->set_initial_window_size(wire::ChannelWindowSize);
    authInfo->handoff_info.channel_info->set_max_packet_size(wire::ChannelMaxPacketSize);
    authInfo->handoff_info.pty_info = std::make_unique<SSHDownstreamPTYInfo>();
    authInfo->handoff_info.pty_info->set_term_env("xterm-256color");
    authInfo->handoff_info.pty_info->set_width_columns(80);
    authInfo->handoff_info.pty_info->set_height_rows(24);
    authInfo->handoff_info.pty_info->set_width_px(300);
    authInfo->handoff_info.pty_info->set_height_px(250);
    authInfo->allow_response = std::make_unique<AllowResponse>();
    authInfo->allow_response->set_username("foo");
    authInfo->allow_response->mutable_upstream()->set_hostname("example");
    auto* publicKeyMethod = authInfo->allow_response->mutable_upstream()->add_allowed_methods();
    publicKeyMethod->set_method("publickey");
    PublicKeyAllowResponse publicKeyMethodData;
    Permissions permissions;
    permissions.set_permit_port_forwarding(true);
    permissions.set_permit_agent_forwarding(true);
    permissions.set_permit_x11_forwarding(true);
    permissions.set_permit_pty(true);
    permissions.set_permit_user_rc(true);
    *permissions.mutable_valid_start_time() = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(
      absl::ToUnixNanos(absl::Now()));
    *permissions.mutable_valid_end_time() = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(
      absl::ToUnixNanos(absl::Now() + absl::Hours(1)));
    *publicKeyMethodData.mutable_permissions() = std::move(permissions);
    publicKeyMethod->mutable_method_data()->PackFrom(publicKeyMethodData);
    return authInfo;
  }

  [[nodiscard]] uint32_t StartTransportHandoff() {
    GenericProxy::MockEncodingContext ctx;
    auto authInfo = BuildHandoffAuthInfo();
    SetDownstreamAuthInfo(authInfo);
    SSHRequestHeaderFrame reqHeaderFrame("example", 0, downstream_filter_state_);
    EXPECT_OK(transport_.encode(reqHeaderFrame, ctx).status());
    DoKeyExchange();
    return authInfo->handoff_info.channel_info->internal_upstream_channel_id();
  }

  [[nodiscard]] uint32_t StartTransportDirectTcpip() {
    GenericProxy::MockEncodingContext ctx;
    auto authInfo = BuildHandoffAuthInfo();
    authInfo->handoff_info.channel_info->set_channel_type("direct-tcpip");
    authInfo->allow_response->mutable_upstream()->set_direct_tcpip(true);
    SetDownstreamAuthInfo(authInfo);
    SSHRequestHeaderFrame reqHeaderFrame("example", 0, downstream_filter_state_);
    wire::ChannelOpenConfirmationMsg expectedMsg;
    expectedMsg.recipient_channel = authInfo->handoff_info.channel_info->downstream_channel_id();
    expectedMsg.sender_channel = authInfo->handoff_info.channel_info->internal_upstream_channel_id();
    expectedMsg.initial_window_size = authInfo->handoff_info.channel_info->initial_window_size();
    expectedMsg.max_packet_size = authInfo->handoff_info.channel_info->max_packet_size();
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{expectedMsg}), _));
    auto r = transport_.encode(reqHeaderFrame, ctx);
    EXPECT_OK(r.status());
    EXPECT_EQ(0, *r); // nothing sent to the upstream
    return authInfo->handoff_info.channel_info->internal_upstream_channel_id();
  }

  // Send and receive packets on a direct-tcpip connection
  absl::Status DoSendRecvDirectTcpip(uint32_t internal_channel_id) {
    // downstream->upstream
    {
      wire::KexInitMsg send{.reserved = 1234};
      Buffer::OwnedImpl packet;
      RETURN_IF_NOT_OK(wire::encodePacket(packet, send, 8, 0).status());
      wire::ChannelDataMsg data{
        .recipient_channel = internal_channel_id,
        .data = wire::flushTo<bytes>(packet),
      };
      // this channel ID should have a bound upstream ID with the same internal ID
      RETURN_IF_NOT_OK(channel_id_manager_->processOutgoingChannelMsg(data, Peer::Upstream));
      EXPECT_EQ(data.recipient_channel, internal_channel_id); // no change
      SSHRequestCommonFrame frame(wire::Message{data});
      GenericProxy::MockEncodingContext ctx;
      RETURN_IF_NOT_OK(transport_.encode(frame, ctx).status());

      wire::KexInitMsg recv;
      RETURN_IF_NOT_OK(ReadMsg(recv));

      EXPECT_EQ(1234, *recv.reserved);
      if (HasFailure()) {
        return absl::InternalError("test failed");
      }
    }
    // upstream->downstream
    {
      wire::KexInitMsg send{.reserved = 2345};
      Buffer::OwnedImpl packet;
      // disable random padding so that we can match the expected packet contents exactly
      RETURN_IF_NOT_OK(wire::encodePacket(packet, send, 8, 0, false).status());
      wire::ChannelDataMsg expected{
        .recipient_channel = internal_channel_id,
        .data = wire::flushTo<bytes>(packet),
      };
      RETURN_IF_NOT_OK(channel_id_manager_->processOutgoingChannelMsg(expected, Peer::Downstream));
      EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{expected})));
      Buffer::OwnedImpl buf;
      RETURN_IF_NOT_OK(wire::encodePacket(buf, send,
                                          server_cipher_->blockSize(openssh::CipherMode::Write),
                                          server_cipher_->aadSize(openssh::CipherMode::Write),
                                          false) // disable random padding
                         .status());
      RETURN_IF_NOT_OK(server_cipher_->encryptPacket(write_seqnum_++, input_buffer_, buf));
      transport_.decode(input_buffer_, false);
      if (HasFailure()) {
        return absl::InternalError("test failed");
      }
    }

    return absl::OkStatus();
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
  StreamInfo::FilterStateImpl downstream_filter_state_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> server_factory_context_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  openssh::SSHKeyPtr server_host_key_;
  testing::NiceMock<Envoy::Network::MockServerConnection> mock_connection_;
  testing::StrictMock<MockClientCodecCallbacks> client_codec_callbacks_;
  std::shared_ptr<ChannelIDManager> channel_id_manager_;
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

  for (uint32_t i = 0; i < 10; i++) {
    uint32_t downstream_id = (1 + i);
    uint32_t upstream_id = (100 + i);
    auto internal_id = *channel_id_manager_->allocateNewChannel(Peer::Downstream);
    ASSERT_OK(channel_id_manager_->bindChannelID(internal_id, PeerLocalID{
                                                                .channel_id = downstream_id,
                                                                .local_peer = Peer::Downstream,
                                                              }));
    wire::ChannelOpenMsg from_downstream;
    from_downstream.channel_type = "session"s;
    from_downstream.sender_channel = internal_id;
    from_downstream.initial_window_size = wire::ChannelWindowSize;
    from_downstream.max_packet_size = wire::ChannelMaxPacketSize;

    ASSERT_OK(WriteFromDownstream(wire::Message{from_downstream}));

    wire::ChannelOpenMsg recv;
    ASSERT_OK(ReadMsg(recv));
    EXPECT_EQ(from_downstream, recv);

    wire::ChannelOpenConfirmationMsg from_upstream;
    from_upstream.recipient_channel = internal_id;
    from_upstream.sender_channel = upstream_id;
    from_upstream.initial_window_size = wire::ChannelWindowSize;
    from_upstream.max_packet_size = wire::ChannelMaxPacketSize;

    {
      auto to_downstream = from_upstream;
      to_downstream.recipient_channel = downstream_id;
      to_downstream.sender_channel = internal_id;
      EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{to_downstream})));
    }
    ASSERT_OK(WriteMsg(wire::Message{from_upstream}));
  }

  for (int i = 0; i < 10; i++) {
    wire::ChannelDataMsg from_upstream;
    from_upstream.recipient_channel = (1000 + i);
    from_upstream.data = to_bytes(fmt::format("hello channel {}", 1000 + i));

    auto to_downstream = from_upstream;
    to_downstream.recipient_channel = (1 + i);
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{to_downstream})));

    ASSERT_OK(WriteMsg(wire::Message{from_upstream}));
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

TEST_F(ClientTransportTest, InvalidUserAuthAllowState) {
  auto authInfo = std::make_shared<AuthInfo>();
  authInfo->server_version = "SSH-2.0-Envoy";
  authInfo->channel_mode = ChannelMode::Normal;
  authInfo->allow_response = std::make_unique<AllowResponse>();
  authInfo->allow_response->set_username("foo");
  authInfo->allow_response->mutable_upstream()->set_hostname("example");
  SetDownstreamAuthInfo(authInfo);

  // omit the publickey allow response
  GenericProxy::MockEncodingContext ctx;
  SSHRequestHeaderFrame reqHeaderFrame("example", 0, downstream_filter_state_);
  ASSERT_OK(transport_.encode(reqHeaderFrame, ctx).status());
  DoKeyExchange();

  ASSERT_OK(ExchangeExtInfo());

  ExpectDisconnectAsHeader(absl::InternalError("missing publickey method in AllowResponse"));
  wire::ServiceRequestMsg clientUserAuthServiceRequest;
  EXPECT_OK(ReadMsg(clientUserAuthServiceRequest));
  EXPECT_EQ("ssh-userauth", clientUserAuthServiceRequest.service_name);

  EXPECT_OK(WriteMsg(wire::Message{wire::ServiceAcceptMsg{.service_name = "ssh-userauth"s}}));
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

TEST_F(ClientTransportTest, Terminate) {
  StartTransportNormal();
  ExpectDisconnectAsHeader(absl::ResourceExhaustedError("test error"));
  transport_.terminate(absl::ResourceExhaustedError("test error"));
}

TEST_F(ClientTransportTest, Handoff) {
  auto internalId = StartTransportHandoff();
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
    ASSERT_EQ(internalId, *req.sender_channel);
    ASSERT_EQ(wire::ChannelWindowSize, *req.initial_window_size);
    ASSERT_EQ(wire::ChannelMaxPacketSize, *req.max_packet_size);

    ASSERT_OK(WriteMsg(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = internalId,
      .sender_channel = 300,
      .initial_window_size = wire::ChannelWindowSize,
      .max_packet_size = wire::ChannelMaxPacketSize,
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
      transport_.authInfo().handoff_info.handoff_in_progress = false;
    });

  ASSERT_OK(WriteMsg(wire::ChannelSuccessMsg{
    .recipient_channel = internalId,
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
      .recipient_channel = 300,
      .data = "foo"_bytes,
    }));
    wire::ChannelDataMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
    ASSERT_EQ("foo"_bytes, *msg.data);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelSuccessMsg{
      .recipient_channel = 300,
    }));
    wire::ChannelSuccessMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelFailureMsg{
      .recipient_channel = 300,
    }));
    wire::ChannelFailureMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelOpenConfirmationMsg{
      .recipient_channel = 300,
    }));
    wire::ChannelOpenConfirmationMsg msg;
    ASSERT_OK(ReadMsg(msg));
    ASSERT_EQ(300, *msg.recipient_channel);
  }
  {
    ASSERT_OK(WriteFromDownstream(wire::ChannelOpenFailureMsg{
      .recipient_channel = 300,
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
    wire::ChannelDataMsg fromUpstream{
      .recipient_channel = internalId,
      .data = "bar"_bytes,
    };
    wire::ChannelDataMsg toDownstream = fromUpstream;
    ASSERT_OK(channel_id_manager_->processOutgoingChannelMsg(toDownstream, Peer::Downstream));
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{fromUpstream}));
  }

  {
    wire::ChannelSuccessMsg fromUpstream{.recipient_channel = internalId};
    wire::ChannelSuccessMsg toDownstream = fromUpstream;
    ASSERT_OK(channel_id_manager_->processOutgoingChannelMsg(toDownstream, Peer::Downstream));
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{fromUpstream}));
  }

  {
    wire::ChannelFailureMsg fromUpstream{.recipient_channel = internalId};
    wire::ChannelFailureMsg toDownstream = fromUpstream;
    ASSERT_OK(channel_id_manager_->processOutgoingChannelMsg(toDownstream, Peer::Downstream));
    EXPECT_CALL(client_codec_callbacks_, onDecodingSuccess(FrameContainingMsg(wire::Message{toDownstream})));
    ASSERT_OK(WriteMsg(wire::Message{fromUpstream}));
  }

  // the client still drops these messages
  ASSERT_OK(WriteMsg(wire::Message{wire::IgnoreMsg{}}));
  ASSERT_OK(WriteMsg(wire::Message{wire::DebugMsg{}}));
  ASSERT_OK(WriteMsg(wire::Message{wire::UnimplementedMsg{}}));
}

TEST_F(ClientTransportTest, Handoff_UserAuthFailure) {
  auto _ = StartTransportHandoff();
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
  auto authInfo = BuildHandoffAuthInfo();
  authInfo->handoff_info.pty_info->mutable_term_env()->resize(wire::MaxPacketSize);
  SetDownstreamAuthInfo(authInfo);

  GenericProxy::MockEncodingContext ctx;
  SSHRequestHeaderFrame reqHeaderFrame("example", 0, downstream_filter_state_);
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
    .recipient_channel = authInfo->handoff_info.channel_info->internal_upstream_channel_id(),
    .sender_channel = 300,
    .initial_window_size = wire::ChannelWindowSize,
    .max_packet_size = wire::ChannelMaxPacketSize,
  }));
}

TEST_F(ClientTransportTest, Handoff_NoDownstreamPty) {
  GenericProxy::MockEncodingContext ctx;
  auto authInfo = BuildHandoffAuthInfo();
  authInfo->handoff_info.pty_info = nullptr;
  SetDownstreamAuthInfo(authInfo);

  SSHRequestHeaderFrame reqHeaderFrame("example", 0, downstream_filter_state_);
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
    .recipient_channel = authInfo->handoff_info.channel_info->internal_upstream_channel_id(),
    .sender_channel = 300,
    .initial_window_size = wire::ChannelWindowSize,
    .max_packet_size = wire::ChannelMaxPacketSize,
  }));
}

TEST_F(ClientTransportTest, Handoff_ChannelOpenFailure) {
  auto internalId = StartTransportHandoff();
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
    .recipient_channel = internalId,
    .description = "test error"s,
  }));
}

TEST_F(ClientTransportTest, Handoff_PtyOpenFailure) {
  auto internalId = StartTransportHandoff();
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
    .recipient_channel = internalId,
    .sender_channel = 300,
    .initial_window_size = wire::ChannelWindowSize,
    .max_packet_size = wire::ChannelMaxPacketSize,
  }));

  wire::ChannelRequestMsg cr;
  ASSERT_OK(ReadMsg(cr));

  ExpectDisconnectAsHeader(absl::InternalError("failed to open upstream tty"));
  ASSERT_OK(WriteMsg(wire::ChannelFailureMsg{
    .recipient_channel = internalId,
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
  auto internalId = StartTransportHandoff();
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
    .recipient_channel = internalId,
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
      transport_.authInfo().handoff_info.handoff_in_progress = false;
    });

  ASSERT_OK(WriteMsg(wire::ChannelSuccessMsg{.recipient_channel = internalId}));

  wire::ChannelRequestMsg shellChannelRequest;
  ASSERT_OK(ReadMsg(shellChannelRequest));
  shellChannelRequest.request.visit(
    [](wire::ShellChannelRequestMsg&) {},
    [](auto&) {
      FAIL() << "unexpected message";
    });
}

TEST_F(ClientTransportTest, HandleRekeyAfterHandoff) {
  auto internalId = StartTransportHandoff();
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
    .recipient_channel = internalId,
    .sender_channel = 300,
    .initial_window_size = wire::ChannelWindowSize,
    .max_packet_size = wire::ChannelMaxPacketSize,
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
      transport_.authInfo().handoff_info.handoff_in_progress = false;
    });

  ASSERT_OK(WriteMsg(wire::ChannelSuccessMsg{.recipient_channel = internalId}));

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
  auto internalId = StartTransportDirectTcpip();

  ASSERT_OK(DoSendRecvDirectTcpip(internalId));

  // close the channel from the downstream
  {
    wire::ChannelCloseMsg close{.recipient_channel = internalId};

    SSHRequestCommonFrame frame(wire::Message{close});
    GenericProxy::MockEncodingContext ctx;
    ASSERT_EQ(absl::CancelledError("channel closed"), transport_.encode(frame, ctx).status());
  }
}

TEST_F(ClientTransportTest, DirectTcpipMode_HandleEOF) {
  server_cipher_ = std::make_unique<PacketCipher>(std::make_unique<NoCipher>(),
                                                  std::make_unique<NoCipher>());
  auto internalId = StartTransportDirectTcpip();

  ASSERT_OK(DoSendRecvDirectTcpip(internalId));

  // send EOF from the downstream
  {
    wire::ChannelEOFMsg eof{.recipient_channel = internalId};

    SSHRequestCommonFrame frame(wire::Message{eof});
    GenericProxy::MockEncodingContext ctx;
    ASSERT_EQ(absl::CancelledError("EOF"), transport_.encode(frame, ctx).status());
  }
}

TEST_F(ClientTransportTest, DirectTcpipMode_WrongMessageTypeReceived) {
  server_cipher_ = std::make_unique<PacketCipher>(std::make_unique<NoCipher>(),
                                                  std::make_unique<NoCipher>());
  auto internalId = StartTransportDirectTcpip();
  (void)internalId;
  SSHRequestCommonFrame frame(wire::Message{wire::DebugMsg{}});
  GenericProxy::MockEncodingContext ctx;
  ASSERT_EQ(absl::InvalidArgumentError("unexpected message of type Debug (4) on direct-tcpip channel"),
            transport_.encode(frame, ctx).status());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec