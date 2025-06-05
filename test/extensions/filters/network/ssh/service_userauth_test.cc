#include "absl/random/random.h"
#include "gtest/gtest.h"
#include "test/test_common/utility.h"

#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/mocks/api/mocks.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

TEST(UserAuthServiceTest, SplitUsername) {
  ASSERT_EQ((std::pair{"", ""}), detail::splitUsername(""));
  ASSERT_EQ((std::pair{"foo", "bar"}), detail::splitUsername("foo@bar"));
  ASSERT_EQ((std::pair{"foo@bar", "baz"}), detail::splitUsername("foo@bar@baz"));
  ASSERT_EQ((std::pair{"foo\0@bar\0"s, "baz"s}), detail::splitUsername("foo\0@bar\0@baz"s));
}

static absl::BitGen rng;

inline bytes randomBytes(size_t size) {
  bytes b;
  b.resize(size);
  for (size_t i = 0; i < b.size(); i++) {
    b[i] = absl::Uniform<uint8_t>(rng);
  }
  return b;
}

std::vector<wire::SshMessageType> ExpectedMessageHandlerTypes{
  wire::SshMessageType::UserAuthRequest,
  wire::SshMessageType::UserAuthSuccess,
  wire::SshMessageType::UserAuthFailure,
  wire::SshMessageType::UserAuthPubKeyOk,
  wire::SshMessageType::UserAuthBanner,
  wire::SshMessageType::UserAuthInfoResponse,
  wire::SshMessageType::ExtInfo,
};

class TestSshMessageDispatcher : public SshMessageDispatcher {
public:
  using SshMessageDispatcher::dispatch_;
  using SshMessageDispatcher::middlewares_;
};

class TestStreamMgmtServerMessageDispatcher : public StreamMgmtServerMessageDispatcher {
public:
  using StreamMgmtServerMessageDispatcher::dispatch_;
};

class DownstreamUserAuthServiceTest : public testing::Test {
public:
  DownstreamUserAuthServiceTest() {
    auto privKeyPath = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_1", 0600);
    *codecCfg.mutable_user_ca_key() = privKeyPath;

    transport_ = std::make_unique<testing::StrictMock<MockDownstreamTransportCallbacks>>();
    EXPECT_CALL(*transport_, codecConfig())
        .WillRepeatedly(ReturnRef(codecCfg));

    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<DownstreamUserAuthService>(*transport_, *api_);
  }

protected:
  pomerium::extensions::ssh::CodecConfig codecCfg;
  std::unique_ptr<testing::StrictMock<MockDownstreamTransportCallbacks>> transport_;
  std::unique_ptr<testing::StrictMock<Api::MockApi>> api_;
  std::unique_ptr<DownstreamUserAuthService> service_;
};

TEST_F(DownstreamUserAuthServiceTest, Name) {
  ASSERT_EQ("ssh-userauth", service_->name());
}

TEST_F(DownstreamUserAuthServiceTest, RegisterSsh) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  ASSERT_EQ(ExpectedMessageHandlerTypes.size(), d.dispatch_.size());
  for (auto t : ExpectedMessageHandlerTypes) {
    ASSERT_EQ(service_.get(), d.dispatch_[t]);
  }
}

TEST_F(DownstreamUserAuthServiceTest, RegisterStreamMgmt) {
  TestStreamMgmtServerMessageDispatcher d;
  service_->registerMessageHandlers(d);

  ASSERT_EQ(1, d.dispatch_.size());
  ASSERT_EQ(service_.get(), d.dispatch_[ServerMessage::kAuthResponse]);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshNoneAuth) {
  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-userauth"s;
  req.request = wire::NoneAuthRequestMsg{};

  wire::Message resp;
  EXPECT_CALL(*transport_, sendMessageToConnection(_))
    .WillOnce(DoAll(SaveArg<0>(&resp),
                    Return(absl::UnknownError("sentinel"))));

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(r, absl::UnknownError("sentinel"));

  ASSERT_EQ(wire::SshMessageType::UserAuthFailure, resp.msg_type());
  wire::UserAuthFailureMsg failure = resp.message.get<wire::UserAuthFailureMsg>();
  ASSERT_EQ((string_list{"publickey"}), failure.methods);
  ASSERT_FALSE(failure.partial);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyInvalidKey) {
  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-userauth"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "AAAA"s,
    .public_key = "AAAA"_bytes,
  };

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(r.code(), absl::StatusCode::kInvalidArgument);
  ASSERT_EQ(r.message(), "invalid format");
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyNoSignature) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());
  auto public_key_blob = (*key)->toPublicKeyBlob();

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-userauth"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = public_key_blob,
  };

  wire::Message resp;
  EXPECT_CALL(*transport_, sendMessageToConnection(_))
    .WillOnce(DoAll(SaveArg<0>(&resp),
                    Return(absl::UnknownError("sentinel"))));

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(r, absl::UnknownError("sentinel"));

  ASSERT_EQ(wire::SshMessageType::UserAuthPubKeyOk, resp.msg_type());
  wire::UserAuthPubKeyOkMsg pubkey_ok_msg =
    resp.message.get<wire::detail::overload_set_for_t<wire::UserAuthPubKeyOkMsg>>()
      .resolve<wire::UserAuthPubKeyOkMsg>()->get();
  ASSERT_EQ("ssh-ed25519", pubkey_ok_msg.public_key_alg);
  ASSERT_EQ(public_key_blob, pubkey_ok_msg.public_key);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyInvalidSignature) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-userauth"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = true,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = (*key)->toPublicKeyBlob(),
    .signature = "AAAA"_bytes,
  };

  bytes session_id = "SESSION-ID"_bytes;

  EXPECT_CALL(*transport_, sessionId())
    .WillOnce(ReturnRef(session_id));

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_FALSE(r.ok());
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyValidSignature) {
  auto privKeyPath = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_1", 0600);
  auto key = openssh::SSHKey::fromPrivateKeyFile(privKeyPath);
  ASSERT_OK(key.status());

  auto public_key_blob = (*key)->toPublicKeyBlob();
  bytes session_id = "SESSION-ID"_bytes;

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-userauth"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = true,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = public_key_blob,
    .signature = to_bytes(absl::HexStringToBytes("0000000b7373682d6564323535313900000040b99ec9b6262fbf1e2c201c604e0bddf46e9c3c5a44c2e47bf44551d2c30c9b7084612167b4bd08bd0d79532944917fb95004c34f4260a321453616f99b531304")),
  };

  EXPECT_CALL(*transport_, sessionId())
    .WillOnce(ReturnRef(session_id));

  pomerium::extensions::ssh::ClientMessage client_msg;
  EXPECT_CALL(*transport_, sendMgmtClientMessage(_))
    .WillOnce(SaveArg<0>(&client_msg));

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_OK(r);

  ASSERT_TRUE(client_msg.has_auth_request());
  auto auth_request = client_msg.auth_request();
  ASSERT_EQ("ssh", auth_request.protocol());
  ASSERT_EQ("publickey", auth_request.auth_method());
  pomerium::extensions::ssh::PublicKeyMethodRequest method_req;
  ASSERT_TRUE(auth_request.method_request().UnpackTo(&method_req));
  ASSERT_EQ(public_key_blob, to_bytes(method_req.public_key()));
  ASSERT_EQ("ssh-ed25519", method_req.public_key_alg());
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshKeyboardInteractive) {
  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-userauth"s;
  req.request = wire::KeyboardInteractiveUserAuthRequestMsg{
    .submethods = string_list{"method-one", "method-two"},
  };

  pomerium::extensions::ssh::ClientMessage client_msg;
  EXPECT_CALL(*transport_, sendMgmtClientMessage(_))
    .WillOnce(SaveArg<0>(&client_msg));

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_OK(r);

  ASSERT_TRUE(client_msg.has_auth_request());
  auto auth_request = client_msg.auth_request();
  ASSERT_EQ("ssh", auth_request.protocol());
  ASSERT_EQ("keyboard-interactive", auth_request.auth_method());
  pomerium::extensions::ssh::KeyboardInteractiveMethodRequest method_req;
  ASSERT_TRUE(auth_request.method_request().UnpackTo(&method_req));
  ASSERT_EQ(2, method_req.submethods_size());
  ASSERT_EQ("method-one", method_req.submethods()[0]);
  ASSERT_EQ("method-two", method_req.submethods()[1]);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshKeyboardInteractiveResponse) {
  wire::UserAuthInfoResponseMsg resp {
    .responses = string_list{"response-one", "response-two"},
  };

  pomerium::extensions::ssh::ClientMessage client_msg;
  EXPECT_CALL(*transport_, sendMgmtClientMessage(_))
    .WillOnce(SaveArg<0>(&client_msg));

  auto r = service_->handleMessage(wire::Message{resp});
  ASSERT_OK(r);

  ASSERT_TRUE(client_msg.has_info_response());
  auto info_response = client_msg.info_response();
  pomerium::extensions::ssh::KeyboardInteractiveInfoPromptResponses responses;
  ASSERT_TRUE(info_response.response().UnpackTo(&responses));
  ASSERT_EQ(2, responses.responses_size());
  ASSERT_EQ("response-one", responses.responses()[0]);
  ASSERT_EQ("response-two", responses.responses()[1]);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshUnknownType) {
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_OK(r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshUnsupportedAuthRequest) {
  // Construct a UserAuthRequestMsg with an unknown request type. Due to the design of
  // the sub_message struct this requires decoding from the wire format.
  Buffer::OwnedImpl buf;
  static wire::field<std::string, wire::LengthPrefixed> username = "foo@bar"s;
  static wire::field<std::string, wire::LengthPrefixed> service_name = "ssh-userauth"s;
  static wire::field<std::string, wire::LengthPrefixed> method_name = "UNKNOWN"s;
  static wire::field<std::string, wire::LengthPrefixed> data = "UNKNOWN-DATA"s;
  ASSERT_OK(wire::encodeMsg(buf, wire::SshMessageType::UserAuthRequest,
                                 username,
                                 service_name,
                                 method_name,
                                 data).status());
  wire::UserAuthRequestMsg user_auth;
  ASSERT_OK(user_auth.decode(buf, buf.length()).status());

  auto r = service_->handleMessage(wire::Message{user_auth});
  ASSERT_EQ(r.code(), absl::StatusCode::kUnimplemented);
  ASSERT_EQ(r.message(), "unknown or unsupported auth method");
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerAllowUpstream) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto allow = msg->mutable_auth_response()->mutable_allow();
  auto upstream = allow->mutable_upstream();
  upstream->set_hostname("example-hostname");
  EXPECT_CALL(*transport_, streamId())
    .WillOnce(Return(42));
  wire::ExtInfoMsg ext_info;
  wire::test::populateFields(ext_info);
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(ext_info));

  AuthStateSharedPtr state;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&state));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);

  ASSERT_THAT(*state->allow_response, Envoy::ProtoEq(*allow));
  ASSERT_EQ(42, state->stream_id);
  ASSERT_EQ(*state->downstream_ext_info, ext_info);
  ASSERT_EQ(ChannelMode::Normal, state->channel_mode);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerAllowInternal) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto allow = msg->mutable_auth_response()->mutable_allow();
  auto internal = allow->mutable_internal();
  ProtobufWkt::Value v;
  v.set_string_value("example-metadata-value");
  ProtobufWkt::Struct metadata_struct{};
  (*metadata_struct.mutable_fields())["example-metadata-key"] = v;
  auto filter_metadata = *internal->mutable_set_metadata()->mutable_filter_metadata();
  filter_metadata["example-filter-name"] = metadata_struct;

  EXPECT_CALL(*transport_, streamId())
    .WillOnce(Return(42));
  wire::ExtInfoMsg ext_info;
  wire::test::populateFields(ext_info);
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(ext_info));

  AuthStateSharedPtr state;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&state));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);

  ASSERT_THAT(*state->allow_response, Envoy::ProtoEq(*allow));
  ASSERT_EQ(42, state->stream_id);
  ASSERT_EQ(*state->downstream_ext_info, ext_info);
  ASSERT_EQ(ChannelMode::Hijacked, state->channel_mode);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerAllowUnsupportedTarget) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response()->mutable_allow();
  EXPECT_CALL(*transport_, streamId())
    .WillOnce(Return(42));
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(wire::ExtInfoMsg{}));
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(r.code(), absl::StatusCode::kInternal);
  ASSERT_EQ(r.message(), "invalid target");
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerDeny) {
  auto server_msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto deny = server_msg->mutable_auth_response()->mutable_deny();
  deny->set_partial(true);
  deny->add_methods("publickey");
  deny->add_methods("keyboard-interactive");

  wire::Message ssh_msg;
  EXPECT_CALL(*transport_, sendMessageToConnection(_))
    .WillOnce(DoAll(SaveArg<0>(&ssh_msg),
                Return(absl::UnknownError("sentinel"))));

  auto r = service_->handleMessage(std::move(server_msg));
  ASSERT_EQ(r, absl::UnknownError("sentinel"));

  ASSERT_EQ(wire::SshMessageType::UserAuthFailure, ssh_msg.msg_type());
  auto failure_msg = ssh_msg.message.get<wire::UserAuthFailureMsg>();
  ASSERT_TRUE(failure_msg.partial);
  ASSERT_EQ((string_list{"publickey", "keyboard-interactive"}), failure_msg.methods);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerDenyNoMethods) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response()->mutable_deny();
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(r.code(), absl::StatusCode::kPermissionDenied);
  ASSERT_EQ(r.message(), "");
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerInfoRequest) {
  auto server_msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto req = server_msg->mutable_auth_response()->mutable_info_request();
  req->set_method("keyboard-interactive");
  pomerium::extensions::ssh::KeyboardInteractiveInfoPrompts prompts{};
  prompts.set_name("prompts-name");
  prompts.set_instruction("prompts-instruction");
  auto prompt1 = prompts.add_prompts();
  prompt1->set_echo(true);
  prompt1->set_prompt("username");
  auto prompt2 = prompts.add_prompts();
  prompt2->set_prompt("password");
  req->mutable_request()->PackFrom(prompts);

  wire::Message ssh_msg;
  EXPECT_CALL(*transport_, sendMessageToConnection(_))
    .WillOnce(DoAll(SaveArg<0>(&ssh_msg),
                Return(absl::UnknownError("sentinel"))));

  auto r = service_->handleMessage(std::move(server_msg));
  ASSERT_EQ(r, absl::UnknownError("sentinel"));

  ASSERT_EQ(wire::SshMessageType::UserAuthInfoRequest, ssh_msg.msg_type());
  auto request_msg =
    ssh_msg.message.get<wire::detail::overload_set_for_t<wire::UserAuthInfoRequestMsg>>()
      .resolve<wire::UserAuthInfoRequestMsg>()->get();
  ASSERT_EQ("prompts-name", request_msg.name);
  ASSERT_EQ("prompts-instruction", request_msg.instruction);
  ASSERT_EQ(2, request_msg.prompts->size());
  ASSERT_TRUE(request_msg.prompts[0].echo);
  ASSERT_EQ("username", request_msg.prompts[0].prompt);
  ASSERT_FALSE(request_msg.prompts[1].echo);
  ASSERT_EQ("password", request_msg.prompts[1].prompt);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerInfoRequestUnsupportedMethod) {
  auto server_msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto req = server_msg->mutable_auth_response()->mutable_info_request();
  req->set_method("unsupported-method");

  auto r = service_->handleMessage(std::move(server_msg));
  ASSERT_EQ(r.code(), absl::StatusCode::kInvalidArgument);
  ASSERT_EQ(r.message(), "unknown method");
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerUnsupportedAuthResponse) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response();
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(r.code(), absl::StatusCode::kInternal);
  ASSERT_EQ(r.message(), "server sent invalid response case");
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerUnsupportedMessage) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(r.code(), absl::StatusCode::kInternal);
  ASSERT_EQ(r.message(), "server sent invalid message case");
}

class UpstreamUserAuthServiceTest : public testing::Test {
public:
  UpstreamUserAuthServiceTest() {
    auto privKeyPath = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_1", 0600);
    *codecCfg.mutable_user_ca_key() = privKeyPath;

    transport_ = std::make_unique<testing::StrictMock<MockTransportCallbacks>>();
    EXPECT_CALL(*transport_, codecConfig())
        .WillRepeatedly(ReturnRef(codecCfg));

    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<UpstreamUserAuthService>(*transport_, *api_);
  }

protected:
  pomerium::extensions::ssh::CodecConfig codecCfg;
  std::unique_ptr<testing::StrictMock<MockTransportCallbacks>> transport_;
  std::unique_ptr<testing::StrictMock<Api::MockApi>> api_;
  std::unique_ptr<UpstreamUserAuthService> service_;
};

TEST_F(UpstreamUserAuthServiceTest, Name) {
  ASSERT_EQ("ssh-userauth", service_->name());
}

TEST_F(UpstreamUserAuthServiceTest, RegisterSsh) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  ASSERT_EQ(ExpectedMessageHandlerTypes.size(), d.dispatch_.size());
  for (auto t : ExpectedMessageHandlerTypes) {
    ASSERT_EQ(service_.get(), d.dispatch_[t]);
  }
}

TEST_F(UpstreamUserAuthServiceTest, RequestService) {
    wire::ServiceRequestMsg expectedRequest{ .service_name = "ssh-userauth"s };
    wire::Message msg{expectedRequest};
    EXPECT_CALL(*transport_, sendMessageToConnection(Eq(msg)))
      .WillOnce(Return(0));

    auto r = service_->requestService();
    EXPECT_OK(r);
}

TEST_F(UpstreamUserAuthServiceTest, InterceptMessage) {
  wire::Message msg{wire::UserAuthSuccessMsg{}};
  auto r = service_->interceptMessage(msg);
  ASSERT_OK(r.status());
  ASSERT_EQ(*r, Continue | UninstallSelf);
}

TEST_F(UpstreamUserAuthServiceTest, InterceptMessageWrongType) {
    wire::Message msg{wire::DebugMsg{}};
    auto r = service_->interceptMessage(msg);
    ASSERT_EQ(r.status().code(), absl::StatusCode::kFailedPrecondition);
    ASSERT_EQ(r.status().message(), "received out-of-order message during auth: expected UserAuthSuccess (52), got Debug (4)");
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageServiceAcceptBadAuthState) {
  AuthState state;
  EXPECT_CALL(*transport_, authState())
    .WillOnce(ReturnRef(state));
  auto r = service_->handleMessage(wire::Message{wire::ServiceAcceptMsg{}});
  ASSERT_EQ(r.code(), absl::StatusCode::kInternal);
  ASSERT_EQ(r.message(), "missing AllowResponse in auth state");
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageUserAuthBannerChannelNormal) {
  AuthState state;
  state.channel_mode = ChannelMode::Normal;
  EXPECT_CALL(*transport_, authState())
    .WillOnce(ReturnRef(state));

  wire::UserAuthBannerMsg banner{};
  wire::test::populateFields(banner);
  wire::Message msg{banner};

  EXPECT_CALL(*transport_, forward(Eq(msg), FrameTags{}));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageUserAuthBannerChannelHijacked) {
  AuthState state;
  state.channel_mode = ChannelMode::Hijacked;
  EXPECT_CALL(*transport_, authState())
    .WillOnce(ReturnRef(state));

  wire::UserAuthBannerMsg banner{};
  wire::test::populateFields(banner);
  wire::Message msg{banner};

  // The banner message should not be forwarded downstream.

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageExtInfo) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  wire::ExtInfoMsg ext_info{};
  wire::test::populateFields(ext_info);

  auto r = service_->handleMessage(wire::Message{ext_info});
  ASSERT_OK(r);
  ASSERT_EQ(1, d.middlewares_.size());
  ASSERT_EQ(service_.get(), d.middlewares_.front());

  // We don't expect to receieve more than one ExtInfo message.
  r = service_->handleMessage(wire::Message{ext_info});
  ASSERT_EQ(r.code(), absl::StatusCode::kFailedPrecondition);
  ASSERT_EQ(r.message(), "unexpected ExtInfoMsg received");
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthSuccessNoPeerExtInfo) {
  // We need to first send a ServiceAcceptMsg to initialize some internal state.
  AuthState state;
  state.allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
  state.allow_response->set_username("example-username");
  EXPECT_CALL(*transport_, authState())
    .WillRepeatedly(ReturnRef(state));
  auto streamId = "stream-id"_bytes;
  EXPECT_CALL(*transport_, sessionId())
    .WillOnce(ReturnRef(streamId));
  EXPECT_CALL(*transport_, sendMessageToConnection(_))
    .WillOnce(Return(123));
  ASSERT_OK(service_->handleMessage(wire::Message{wire::ServiceAcceptMsg{}}));

  wire::Message msg{wire::UserAuthSuccessMsg{}};

  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(std::nullopt));

  EXPECT_CALL(*transport_, forward(Eq(msg), Eq(FrameTags::EffectiveHeader)));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthSuccessOutOfOrder) {
  // We don't expect a UserAuthSuccessMsg first.
  auto r = service_->handleMessage(wire::Message{wire::UserAuthSuccessMsg{}});
  ASSERT_EQ(r.code(), absl::StatusCode::kFailedPrecondition);
  ASSERT_EQ(r.message(), "unexpected UserAuthSuccessMsg received");
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthFailure) {
  wire::UserAuthFailureMsg msg{};
  auto r = service_->handleMessage(wire::Message{msg});
  ASSERT_EQ(r.code(), StatusCode::kPermissionDenied);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageUnknownType) {
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_OK(r);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec