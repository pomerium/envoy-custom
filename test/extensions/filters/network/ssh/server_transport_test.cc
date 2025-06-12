
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

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class ServerTransportTest : public testing::Test {
public:
  ServerTransportTest()
      : api_(Api::createApiForTest()),
        client_host_key_(*openssh::SSHKey::generate(KEY_ED25519, 256)),
        client_(std::make_shared<testing::StrictMock<Grpc::MockAsyncClient>>()),
        transport_(*api_, initConfig(), [this] { return this->client_; }, nullptr) {
  }

  void SetUp() {
    EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
      .WillOnce(Return(&stream_));
    transport_.setCodecCallbacks(server_codec_callbacks_);
    ON_CALL(server_codec_callbacks_, writeToConnection(_))
      .WillByDefault([this](Envoy::Buffer::Instance& buffer) {
        output_buffer_.move(buffer);
      });
    EXPECT_CALL(server_codec_callbacks_, writeToConnection(_))
      .Times(AnyNumber());
    ON_CALL(server_codec_callbacks_, connection())
      .WillByDefault(Return(makeOptRef<Network::Connection>(mock_connection_)));
    ON_CALL(server_codec_callbacks_, onDecodingFailure(_))
      .WillByDefault([](std::string_view err) {
        ADD_FAILURE() << err;
      });

    // Perform a manual key exchange as the client and set up a packet cipher
    input_buffer_.add("SSH-2.0-TestClient\r\n");
    transport_.decode(input_buffer_, false);
    EXPECT_TRUE(output_buffer_.startsWith("SSH-2.0-Envoy\r\n"));
    output_buffer_.drain(15);
    wire::KexInitMsg serverKexInit;
    ASSERT_OK(wire::decodePacket(output_buffer_, serverKexInit).status());
    wire::KexInitMsg clientKexInit{
      .cookie = {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
      .kex_algorithms = {{"curve25519-sha256"s, "ext-info-c"s, "kex-strict-c-v00@openssh.com"s}},
      .server_host_key_algorithms = {{"ssh-ed25519"s}},
      .encryption_algorithms_client_to_server = {{"chacha20-poly1305@openssh.com"s}},
      .encryption_algorithms_server_to_client = {{"chacha20-poly1305@openssh.com"s}},
      .compression_algorithms_client_to_server = {{"none"s}},
      .compression_algorithms_server_to_client = {{"none"s}},
    };
    ASSERT_OK(wire::encodePacket(input_buffer_, clientKexInit, 8, 0).status());
    transport_.decode(input_buffer_, false);
    HandshakeMagics magics{
      .client_version = "SSH-2.0-TestClient\r\n"_bytes,
      .server_version = "SSH-2.0-Envoy\r\n"_bytes,
      .client_kex_init = *wire::encodeTo<bytes>(clientKexInit),
      .server_kex_init = *wire::encodeTo<bytes>(serverKexInit),
    };
    // we can just pick an algorithm, not testing the packet cipher itself here
    Algorithms algs{
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
    DirectionalPacketCipherFactoryRegistry reg;
    reg.registerType<Chacha20Poly1305CipherFactory>();
    Curve25519Sha256KexAlgorithmFactory f;
    auto kexAlg = f.create(&magics, &algs, client_host_key_.get());
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

  absl::Status WriteMsg(seqnum_t seqnum, wire::Message&& msg) { // NOLINT
    Buffer::OwnedImpl buf;
    if (auto n = wire::encodePacket(buf, msg,
                                    client_cipher_->blockSize(openssh::CipherMode::Write),
                                    client_cipher_->aadSize(openssh::CipherMode::Write));
        !n.ok()) {
      return n.status();
    }
    if (auto stat = client_cipher_->encryptPacket(seqnum, input_buffer_, buf); !stat.ok()) {
      return stat;
    }
    transport_.decode(input_buffer_, false);
    return absl::OkStatus();
  }

  absl::Status ReadMsg(seqnum_t seqnum, auto& msg) { // NOLINT
    Buffer::OwnedImpl buf;
    if (auto n = client_cipher_->decryptPacket(seqnum, buf, output_buffer_); !n.ok()) {
      return n.status();
    }
    return wire::decodePacket(buf, msg).status();
  }

  std::shared_ptr<pomerium::extensions::ssh::CodecConfig>& initConfig() {
    server_config_ = std::make_shared<pomerium::extensions::ssh::CodecConfig>();
    for (auto keyName : {"rsa_1", "ed25519_1"}) {
      auto hostKeyFile = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
      server_config_->add_host_keys(hostKeyFile);
    }
    return server_config_;
  }

  std::optional<bytes> current_session_id_;
  std::unique_ptr<PacketCipher> client_cipher_;
  Envoy::Buffer::OwnedImpl input_buffer_;
  Envoy::Buffer::OwnedImpl output_buffer_;
  Api::ApiPtr api_;
  openssh::SSHKeyPtr client_host_key_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> server_config_;
  testing::StrictMock<MockServerCodecCallbacks> server_codec_callbacks_;
  testing::StrictMock<Envoy::Network::MockServerConnection> mock_connection_;
  testing::NiceMock<Grpc::MockAsyncStream> stream_;
  std::shared_ptr<testing::StrictMock<Grpc::MockAsyncClient>> client_;
  SshServerTransport transport_;
};

TEST_F(ServerTransportTest, Disconnect) {
  EXPECT_CALL(server_codec_callbacks_, onDecodingFailure("received disconnect: by application"sv))
    .WillOnce([](std::string_view) {});

  ASSERT_OK(WriteMsg(0, wire::DisconnectMsg{.reason_code = 11}));
}

// Validate the server's initial ExtInfoMsg
TEST_F(ServerTransportTest, InitialExtInfo) {
  wire::ExtInfoMsg serverExtInfo;
  ASSERT_OK(ReadMsg(0, serverExtInfo));
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
  wire::ExtInfoMsg serverExtInfo;
  ASSERT_OK(ReadMsg(0, serverExtInfo));

  Buffer::OwnedImpl buffer;
  wire::write(buffer, wire::SshMessageType(200));
  wire::Message msg;
  EXPECT_OK(msg.decode(buffer, buffer.length()).status());
  EXPECT_FALSE(msg.has_value()); // sanity check

  for (uint32_t i = 0; i < 10; i++) {
    ASSERT_OK(WriteMsg(i, auto(msg)));
    wire::UnimplementedMsg unimplemented;
    ASSERT_OK(ReadMsg(i + 1, unimplemented)); // add 1 since we read serverExtInfo
    EXPECT_EQ(i, unimplemented.sequence_number);
  }
}

TEST_F(ServerTransportTest, HostKeysProve) {
  wire::ExtInfoMsg serverExtInfo;
  ASSERT_OK(ReadMsg(0, serverExtInfo));

  auto hostKeys = openssh::loadHostKeys(server_config_->host_keys());

  std::vector<bytes> hostKeyBlobs;
  for (const auto& hostKey : *hostKeys) {
    hostKeyBlobs.push_back(hostKey->toPublicKeyBlob());
  }

  ASSERT_OK(WriteMsg(0, wire::GlobalRequestMsg{
                          .request = {wire::HostKeysProveRequestMsg{.hostkeys = hostKeyBlobs}},
                        }));
  wire::HostKeysProveResponseMsg response;
  ASSERT_OK(ReadMsg(1, response));
  for (size_t i = 0; i < hostKeys->size(); i++) {
    Envoy::Buffer::OwnedImpl tmp;
    wire::write_opt<wire::LengthPrefixed>(tmp, "hostkeys-prove-00@openssh.com"s);
    wire::write_opt<wire::LengthPrefixed>(tmp, *current_session_id_);
    wire::write_opt<wire::LengthPrefixed>(tmp, hostKeyBlobs[i]);
    ASSERT_OK((*hostKeys)[i]->verify(response.signatures[i], wire::flushTo<bytes>(tmp)));
  }
}

class UnexpectedClientMessagesTest : public ServerTransportTest, public testing::WithParamInterface<std::tuple<wire::Message, std::string_view>> {
public:
  void SetUp() override {
    ServerTransportTest::SetUp();
    wire::ExtInfoMsg serverExtInfo;
    ASSERT_OK(ReadMsg(0, serverExtInfo));
  }
};

TEST_P(UnexpectedClientMessagesTest, UnexpectedClientMessages) {
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
  seqnum_t seqnum = 0;
  ASSERT_OK(WriteMsg(seqnum++, std::move(msg)));
  if (err != "") {
    // for KexInitMsg, the server sends its KexInit reply before checking the algorithms
    if (msg.msg_type() == wire::SshMessageType::KexInit) {
      wire::KexInitMsg serverKexInit;
      ASSERT_OK(ReadMsg(seqnum++, serverKexInit));
    }
    wire::DisconnectMsg serverDisconnect;
    ASSERT_OK(ReadMsg(seqnum++, serverDisconnect));
    EXPECT_THAT(*serverDisconnect.description, HasSubstr(err));
    EXPECT_EQ(2 /*SSH2_DISCONNECT_PROTOCOL_ERROR*/, *serverDisconnect.reason_code);
  }
}

INSTANTIATE_TEST_SUITE_P(UnexpectedClientMessages, UnexpectedClientMessagesTest,
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

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec