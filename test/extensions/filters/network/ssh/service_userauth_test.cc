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

class TestSshMessageDispatcher : public SshMessageDispatcher {
public:
  using SshMessageDispatcher::dispatch;
  using SshMessageDispatcher::dispatch_;
};

class TestStreamMgmtServerMessageDispatcher : public StreamMgmtServerMessageDispatcher {
public:
  using StreamMgmtServerMessageDispatcher::dispatch_;
};

class DownstreamUserAuthServiceTest : public testing::Test {
public:
  DownstreamUserAuthServiceTest() {
    auto privKeyPath = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_1", 0600);
    codecCfg.mutable_user_ca_key()->set_filename(privKeyPath);

    transport_ = std::make_unique<testing::StrictMock<MockDownstreamTransportCallbacks>>();
    EXPECT_CALL(*transport_, codecConfig())
      .WillRepeatedly(ReturnRef(codecCfg));

    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<DownstreamUserAuthService>(*transport_, *api_);
  }

  void SendValidPubKeyRequest(pomerium::extensions::ssh::ClientMessage* out_mgmt_request = nullptr, bytes* out_public_key_blob = nullptr) { // NOLINT
    auto privKeyPath = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_1", 0600);
    auto key = openssh::SSHKey::fromPrivateKeyFile(privKeyPath);
    ASSERT_OK(key.status());

    auto publicKeyBlob = (*key)->toPublicKeyBlob();
    if (out_public_key_blob != nullptr) {
      *out_public_key_blob = publicKeyBlob;
    }
    bytes session_id = "SESSION-ID"_bytes;

    wire::UserAuthRequestMsg req;
    req.username = "foo@bar"s;
    req.service_name = "ssh-connection"s;
    req.request = wire::PubKeyUserAuthRequestMsg{
      .has_signature = true,
      .public_key_alg = "ssh-ed25519"s,
      .public_key = publicKeyBlob,
      .signature = to_bytes(absl::HexStringToBytes("0000000b7373682d6564323535313900000040bf1e4e617a3a1b72dd2d5c066d349e95df08b8d1b0f1f338349fc0db45e89fd0050c42f763dab4512d4b1e5cb109eff77a3cb094a3b7c3aa9a8b2f43c1d9f207")),
    };
    EXPECT_CALL(*transport_, sessionId())
      .WillOnce(ReturnRef(session_id));
    if (out_mgmt_request != nullptr) {
      EXPECT_CALL(*transport_, sendMgmtClientMessage(_))
        .WillOnce(SaveArg<0>(out_mgmt_request));
    } else {
      EXPECT_CALL(*transport_, sendMgmtClientMessage(_));
    }

    auto r = service_->handleMessage(wire::Message{std::move(req)});
    ASSERT_OK(r);
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

  std::vector<wire::SshMessageType> expected_types{
    wire::SshMessageType::UserAuthRequest,
    wire::SshMessageType::UserAuthInfoResponse,
  };

  ASSERT_EQ(expected_types.size(), d.dispatch_.size());
  for (auto t : expected_types) {
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
  req.service_name = "ssh-connection"s;
  req.request = wire::NoneAuthRequestMsg{};

  wire::Message resp;
  EXPECT_CALL(*transport_, sendMessageToConnection(
                             MSG(wire::UserAuthFailureMsg,
                                 AllOf(FIELD_EQ(methods, string_list{"publickey"}),
                                       FIELD_EQ(partial, false)))))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(absl::UnknownError("sentinel"), r);
}

TEST_F(DownstreamUserAuthServiceTest, NoneAuthOnlyAllowedOnce) {
  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::NoneAuthRequestMsg{};

  wire::Message resp;
  EXPECT_CALL(*transport_, sendMessageToConnection(
                             MSG(wire::UserAuthFailureMsg,
                                 AllOf(FIELD_EQ(methods, string_list{"publickey"}),
                                       FIELD_EQ(partial, false)))))
    .WillOnce(Return(0));

  // first request
  ASSERT_OK(service_->handleMessage(wire::Message{req}));

  // second request
  ASSERT_EQ(absl::InvalidArgumentError("invalid auth request"),
            service_->handleMessage(wire::Message{req}));
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyInvalidKey) {
  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "AAAA"s,
    .public_key = "AAAA"_bytes,
  };

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(absl::InvalidArgumentError("invalid format"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyNoSignature) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());
  auto public_key_blob = (*key)->toPublicKeyBlob();

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
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
  ASSERT_EQ(absl::UnknownError("sentinel"), r);

  resp.visit(
    [&](opt_ref<wire::UserAuthPubKeyOkMsg> opt_msg) {
      ASSERT_TRUE(opt_msg.has_value());
      auto& pubkey_ok_msg = opt_msg.value().get();
      ASSERT_EQ("ssh-ed25519", pubkey_ok_msg.public_key_alg);
      ASSERT_EQ(public_key_blob, pubkey_ok_msg.public_key);
    },
    [](auto&) {
      FAIL() << "expected UserAuthPubKeyOkMsg";
    });
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyAlgorithmDoesNotMatch) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "rsa-sha2-512"s,
    .public_key = (*key)->toPublicKeyBlob(),
  };

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(absl::InvalidArgumentError("requested public key algorithm (rsa-sha2-512) does not match the algorithm of the provided key (ssh-ed25519)"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyAlgorithmUnknown) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "not-a-real-algorithm"s,
    .public_key = (*key)->toPublicKeyBlob(),
  };

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(absl::InvalidArgumentError("unsupported public key algorithm: not-a-real-algorithm"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyAlgorithmRsa) {
  for (auto alg : {"rsa-sha2-256"s, "rsa-sha2-512"s}) {
    wire::UserAuthRequestMsg req;
    req.username = "foo@bar"s;
    req.service_name = "ssh-connection"s;
    req.request = wire::PubKeyUserAuthRequestMsg{
      .has_signature = false,
      .public_key_alg = alg,
      .public_key = (*openssh::SSHKey::generate(KEY_RSA, 2048))->toPublicKeyBlob(),
    };

    wire::Message resp;
    EXPECT_CALL(*transport_, sendMessageToConnection(_))
      .WillOnce(DoAll(SaveArg<0>(&resp),
                      Return(0)));
    ASSERT_OK(service_->handleMessage(wire::Message{req}));

    resp.visit(
      [&](opt_ref<wire::UserAuthPubKeyOkMsg>) {},
      [](auto&) {
        FAIL() << "expected UserAuthPubKeyOkMsg";
      });
  }
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKey_TooManyAttempts) {
  for (int i = 0; i < 11; i++) {
    wire::UserAuthRequestMsg req;
    req.username = "foo@bar"s;
    req.service_name = "ssh-connection"s;
    req.request = wire::PubKeyUserAuthRequestMsg{
      .has_signature = false,
      .public_key_alg = "ssh-ed25519"s,
      .public_key = (*openssh::SSHKey::generate(KEY_ED25519, 256))->toPublicKeyBlob(),
    };

    if (i == 10) {
      ASSERT_EQ(absl::InvalidArgumentError("too many attempts"),
                service_->handleMessage(wire::Message{req}));
      break;
    }
    wire::Message resp;
    EXPECT_CALL(*transport_, sendMessageToConnection(_))
      .WillOnce(DoAll(SaveArg<0>(&resp),
                      Return(0)));
    ASSERT_OK(service_->handleMessage(wire::Message{req}));

    resp.visit(
      [&](opt_ref<wire::UserAuthPubKeyOkMsg>) {},
      [](auto&) {
        FAIL() << "expected UserAuthPubKeyOkMsg";
      });
  }
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKey_KeyAlreadyUsed) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = (*key)->toPublicKeyBlob(),
  };

  wire::Message resp;
  EXPECT_CALL(*transport_, sendMessageToConnection(_))
    .WillOnce(DoAll(SaveArg<0>(&resp),
                    Return(0)));
  ASSERT_OK(service_->handleMessage(wire::Message{req}));

  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = (*key)->toPublicKeyBlob(),
  };

  ASSERT_EQ(absl::InvalidArgumentError("key already used"),
            service_->handleMessage(wire::Message{req}));
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyUnexpectedSignature) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = false,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = (*key)->toPublicKeyBlob(),
    .signature = "AAAA"_bytes,
  };

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(absl::InvalidArgumentError("invalid PubKeyUserAuthRequestMsg: unexpected signature"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyEmptySignature) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
  req.request = wire::PubKeyUserAuthRequestMsg{
    .has_signature = true,
    .public_key_alg = "ssh-ed25519"s,
    .public_key = (*key)->toPublicKeyBlob(),
  };

  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_EQ(absl::InvalidArgumentError("invalid PubKeyUserAuthRequestMsg: empty signature"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyInvalidSignature) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
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

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyEncodingFailure) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req;
  std::string username_too_long(wire::MaxPacketSize, 'A');
  req.username = username_too_long;
  req.service_name = "ssh-connection"s;
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
  ASSERT_EQ(absl::InternalError("Aborted: message size too large"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshPubKeyValidSignature) {
  pomerium::extensions::ssh::ClientMessage client_msg;
  bytes public_key_blob;
  SendValidPubKeyRequest(&client_msg, &public_key_blob);

  ASSERT_TRUE(client_msg.has_auth_request());
  auto auth_request = client_msg.auth_request();
  ASSERT_EQ("ssh", auth_request.protocol());
  ASSERT_EQ("publickey", auth_request.auth_method());
  pomerium::extensions::ssh::PublicKeyMethodRequest method_req;
  ASSERT_TRUE(auth_request.method_request().UnpackTo(&method_req));
  ASSERT_EQ(public_key_blob, to_bytes(method_req.public_key()));
  ASSERT_EQ("ssh-ed25519", method_req.public_key_alg());
  auto expectedFp = bytes{0x2f, 0x79, 0x3f, 0xa0, 0x9b, 0x9b, 0x6e, 0x54,
                          0x98, 0xd2, 0x50, 0x7d, 0x52, 0x5b, 0x25, 0xed,
                          0xe9, 0x83, 0x32, 0x74, 0x4f, 0x2a, 0x6f, 0xfc,
                          0xb9, 0xd7, 0xf6, 0x71, 0xcc, 0x24, 0xe7, 0xad};
  ASSERT_EQ(expectedFp, to_bytes(method_req.public_key_fingerprint_sha256()));
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshKeyboardInteractive) {
  wire::UserAuthRequestMsg req;
  req.username = "foo@bar"s;
  req.service_name = "ssh-connection"s;
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
  wire::UserAuthInfoResponseMsg resp{
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

TEST_F(DownstreamUserAuthServiceTest, HandleMessageInvalidUserAuthInfoResponse) {
  // Generate a message with the UserAuthInfoResponse tag but no data.
  Buffer::OwnedImpl buf;
  buf.writeBEInt(wire::SshMessageType::UserAuthInfoResponse);
  wire::Message msg;
  ASSERT_OK(msg.decode(buf, buf.length()).status());

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(absl::InvalidArgumentError("invalid auth response"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshUnknownType) {
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("received unexpected message of type Debug (4)"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageSshUnsupportedAuthRequest) {
  // Construct a UserAuthRequestMsg with an unknown request type.
  wire::UserAuthRequestMsg user_auth;
  user_auth.username = "foo@bar"s;
  user_auth.service_name = "ssh-connection"s;
  user_auth.method_name() = "UNKNOWN";
  Envoy::Buffer::OwnedImpl tmp("UNKNOWN_DATA");
  ASSERT_OK(user_auth.request.decode(tmp, tmp.length()).status());

  auto r = service_->handleMessage(wire::Message{user_auth});
  ASSERT_EQ(absl::UnimplementedError("unknown or unsupported auth method"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerAllowUpstream) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  SendValidPubKeyRequest();

  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto* allow = msg->mutable_auth_response()->mutable_allow();
  allow->mutable_upstream()->set_hostname("example-hostname");

  auto allowCopy = *allow;

  EXPECT_CALL(*transport_, streamId())
    .WillOnce(Return(42));
  wire::ExtInfoMsg ext_info;
  wire::test::populateFields(ext_info);
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(ext_info));

  EXPECT_CALL(*transport_, onServiceAuthenticated("ssh-connection"s));
  AuthStateSharedPtr state;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&state));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);

  ASSERT_THAT(*state->allow_response, Envoy::ProtoEq(allowCopy));
  ASSERT_EQ(42, state->stream_id);
  ASSERT_EQ(*state->downstream_ext_info, ext_info);
  ASSERT_EQ(ChannelMode::Normal, state->channel_mode);

  // check that the service unregistered itself from the message handler
  ASSERT_TRUE(d.dispatch_.empty());
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerAllowInternal) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  SendValidPubKeyRequest();

  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto* allow = msg->mutable_auth_response()->mutable_allow();
  auto* filter_metadata = allow->mutable_internal()->mutable_set_metadata()->mutable_filter_metadata();
  ProtobufWkt::Value v;
  v.set_string_value("example-metadata-value");
  ProtobufWkt::Struct metadata_struct{};
  (*metadata_struct.mutable_fields())["example-metadata-key"] = v;
  (*filter_metadata)["example-filter-name"] = metadata_struct;

  auto allowCopy = *allow;

  EXPECT_CALL(*transport_, streamId())
    .WillOnce(Return(42));
  wire::ExtInfoMsg ext_info;
  wire::test::populateFields(ext_info);
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(ext_info));

  AuthStateSharedPtr state;
  EXPECT_CALL(*transport_, initUpstream(_))
    .WillOnce(SaveArg<0>(&state));

  EXPECT_CALL(*transport_, onServiceAuthenticated("ssh-connection"s));
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);

  ASSERT_THAT(*state->allow_response, Envoy::ProtoEq(allowCopy));
  ASSERT_EQ(42, state->stream_id);
  ASSERT_EQ(*state->downstream_ext_info, ext_info);
  ASSERT_EQ(ChannelMode::Hijacked, state->channel_mode);
  ASSERT_TRUE(d.dispatch_.empty());
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerAllowUnsupportedTarget) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response()->mutable_allow();
  EXPECT_CALL(*transport_, streamId())
    .WillOnce(Return(42));
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(wire::ExtInfoMsg{}));
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(absl::InternalError("invalid target"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerDeny) {
  auto server_msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto* deny = server_msg->mutable_auth_response()->mutable_deny();
  deny->set_partial(true);
  deny->add_methods("publickey");
  deny->add_methods("keyboard-interactive");

  EXPECT_CALL(*transport_, sendMessageToConnection(
                             MSG(wire::UserAuthFailureMsg,
                                 AllOf(FIELD_EQ(methods, string_list{"publickey", "keyboard-interactive"}),
                                       FIELD_EQ(partial, true)))))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  auto r = service_->handleMessage(std::move(server_msg));
  ASSERT_EQ(r, absl::UnknownError("sentinel"));
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerDenyNoMethods) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response()->mutable_deny();
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(absl::PermissionDeniedError(""), r);
}

TEST_F(DownstreamUserAuthServiceTest, AuthFailureLimit) {
  // test that the server will disconnect after a number of failed attempts
  EXPECT_CALL(*transport_, sendMessageToConnection(
                             MSG(wire::UserAuthFailureMsg,
                                 AllOf(FIELD_EQ(methods, string_list{"publickey"}),
                                       FIELD_EQ(partial, false)))))
    .Times(MaxFailedAuthAttempts - 1)
    .WillRepeatedly(Return(0));
  for (int i = 0; i < MaxFailedAuthAttempts - 1; i++) {
    auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
    msg->mutable_auth_response()->mutable_deny()->set_partial(false);
    msg->mutable_auth_response()->mutable_deny()->add_methods("publickey");

    ASSERT_OK(service_->handleMessage(std::move(msg)));
  }

  // the next deny should return an error
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response()->mutable_deny()->set_partial(false);
  msg->mutable_auth_response()->mutable_deny()->add_methods("publickey");
  ASSERT_EQ(absl::PermissionDeniedError("too many authentication failures"),
            service_->handleMessage(std::move(msg)));
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerInfoRequest) {
  auto server_msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto* req = server_msg->mutable_auth_response()->mutable_info_request();
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

  auto matcher = MSG(wire::UserAuthInfoRequestMsg,
                     AllOf(FIELD_EQ(name, "prompts-name"),
                           FIELD_EQ(instruction, "prompts-instruction"),
                           FIELD_EQ(prompts,
                                    std::vector{
                                      wire::UserAuthInfoPrompt{.prompt = "username"s, .echo = true},
                                      wire::UserAuthInfoPrompt{.prompt = "password"s, .echo = false}})));
  EXPECT_CALL(*transport_, sendMessageToConnection(matcher))
    .WillOnce(Return(absl::UnknownError("sentinel")));

  auto r = service_->handleMessage(std::move(server_msg));
  ASSERT_EQ(r, absl::UnknownError("sentinel"));
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerInfoRequestUnsupportedMethod) {
  auto server_msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto* req = server_msg->mutable_auth_response()->mutable_info_request();
  req->set_method("unsupported-method");

  auto r = service_->handleMessage(std::move(server_msg));
  ASSERT_EQ(absl::InvalidArgumentError("unknown method"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerUnsupportedAuthResponse) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  msg->mutable_auth_response();
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(absl::InternalError("server sent invalid response case"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleMessageServerUnsupportedMessage) {
  auto msg = std::make_unique<pomerium::extensions::ssh::ServerMessage>();
  auto r = service_->handleMessage(std::move(msg));
  ASSERT_EQ(absl::InternalError("server sent invalid message case"), r);
}

TEST_F(DownstreamUserAuthServiceTest, HandleInconsistentServiceNames) {
  auto key = openssh::SSHKey::generate(KEY_ED25519, 256);
  ASSERT_OK(key.status());

  wire::UserAuthRequestMsg req{
    .username = "foo"s,
    .service_name = "ssh-connection"s,
    .request = wire::NoneAuthRequestMsg{},
  };
  EXPECT_CALL(*transport_, sendMessageToConnection)
    .WillOnce(Return(0));
  auto r = service_->handleMessage(wire::Message{req});
  ASSERT_OK(r);

  wire::UserAuthRequestMsg req2{
    .username = "foo"s,
    .service_name = "not-ssh-connection"s,
    .request = wire::PubKeyUserAuthRequestMsg{.public_key_alg = "foo"s},
  };
  ASSERT_EQ(absl::FailedPreconditionError("inconsistent service names sent in user auth request"),
            service_->handleMessage(wire::Message{req2}));
}

class UpstreamUserAuthServiceTest : public testing::Test {
public:
  UpstreamUserAuthServiceTest() {
    auto privKeyPath = copyTestdataToWritableTmp("regress/unittests/sshkey/testdata/ed25519_1", 0600);
    codec_cfg_.mutable_user_ca_key()->set_filename(privKeyPath);

    transport_ = std::make_unique<testing::StrictMock<MockTransportCallbacks>>();
    EXPECT_CALL(*transport_, codecConfig())
      .WillRepeatedly(ReturnRef(codec_cfg_));
    EXPECT_CALL(*transport_, peerExtInfo())
      .WillRepeatedly([&] { return peer_ext_info_; });

    api_ = std::make_unique<testing::StrictMock<Api::MockApi>>();
    service_ = std::make_unique<UpstreamUserAuthService>(*transport_, *api_);
  }

protected:
  pomerium::extensions::ssh::CodecConfig codec_cfg_;
  std::optional<wire::ExtInfoMsg> peer_ext_info_;
  std::unique_ptr<testing::StrictMock<MockTransportCallbacks>> transport_;
  std::unique_ptr<testing::StrictMock<Api::MockApi>> api_;
  std::unique_ptr<UpstreamUserAuthService> service_;

  // Simulates a call to onServiceAccepted() in a valid auth state, triggering a
  // UserAuthRequestMsg to be sent.
  void triggerUserAuthRequestMsg(wire::Message* out_req = nullptr) {
    AuthState state;
    state.allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
    state.allow_response->set_username("example-username");
    EXPECT_CALL(*transport_, authState())
      .WillRepeatedly(ReturnRef(state));

    wire::Message req;
    EXPECT_CALL(*transport_, sendMessageToConnection(MSG(wire::UserAuthRequestMsg, _)))
      .WillOnce(DoAll(SaveArg<0>(&req),
                      Return(absl::UnknownError("sentinel"))));

    auto r = service_->onServiceAccepted();
    ASSERT_EQ(absl::UnknownError("sentinel"), r);
    if (out_req != nullptr) {
      *out_req = std::move(req);
    }
  }
};

TEST_F(UpstreamUserAuthServiceTest, Name) {
  ASSERT_EQ("ssh-userauth", service_->name());
}

TEST_F(UpstreamUserAuthServiceTest, RegisterSsh) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  std::vector<wire::SshMessageType> expected_types{
    wire::SshMessageType::UserAuthSuccess,
    wire::SshMessageType::UserAuthFailure,
    wire::SshMessageType::UserAuthBanner,
    wire::SshMessageType::ExtInfo,
  };

  ASSERT_EQ(expected_types.size(), d.dispatch_.size());
  for (auto t : expected_types) {
    ASSERT_EQ(service_.get(), d.dispatch_[t]);
  }
}

TEST_F(UpstreamUserAuthServiceTest, RequestService) {
  wire::ServiceRequestMsg expectedRequest{.service_name = "ssh-userauth"s};
  wire::Message msg{expectedRequest};
  EXPECT_CALL(*transport_, sendMessageToConnection(Eq(msg)))
    .WillOnce(Return(0));

  auto r = service_->requestService();
  EXPECT_OK(r);
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedBadAuthState) {
  AuthState state;
  EXPECT_CALL(*transport_, authState())
    .WillOnce(ReturnRef(state));
  auto r = service_->onServiceAccepted();
  ASSERT_EQ(absl::InternalError("missing AllowResponse in auth state"), r);
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedEncodingFailure) {
  AuthState state;
  state.allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
  std::string username_too_long(wire::MaxPacketSize, 'A');
  state.allow_response->set_username(username_too_long);
  EXPECT_CALL(*transport_, authState())
    .WillRepeatedly(ReturnRef(state));
  auto streamId = "stream-id"_bytes;
  EXPECT_CALL(*transport_, sessionId())
    .WillOnce(ReturnRef(streamId));

  auto r = service_->onServiceAccepted();
  ASSERT_EQ(absl::AbortedError("error encoding user auth request: message size too large"), r);
}

void verifySignature(bytes session_id, wire::Message& req, std::string expected_alg) {
  const auto& pubkey_req = req.message.get<wire::UserAuthRequestMsg>()
                             .request.get<wire::PubKeyUserAuthRequestMsg>();
  ASSERT_EQ(expected_alg, *pubkey_req.public_key_alg);
  auto key = openssh::SSHKey::fromPublicKeyBlob(pubkey_req.public_key);
  ASSERT_OK(key.status());
  auto expected_key_type = openssh::SSHKey::keyTypeFromName(expected_alg);
  ASSERT_EQ(expected_key_type, (*key)->keyType());

  Envoy::Buffer::OwnedImpl verifyBuf;
  wire::write_opt<wire::LengthPrefixed>(verifyBuf, session_id);
  auto e = req.encode(verifyBuf);
  ASSERT_OK(e.status());
  auto span = linearizeToSpan(verifyBuf);
  auto payload = span.first(span.size() - 4 - pubkey_req.signature->size());
  ASSERT_OK((*key)->verify(*pubkey_req.signature, payload, expected_alg));
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedValidSignature) {
  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "ssh-ed25519-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsEd25519) {
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "ssh-ed25519",
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521",
      "rsa-sha2-512",
      "rsa-sha2-256",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "ssh-ed25519-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsEcdsaP256) {
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521",
      "rsa-sha2-512",
      "rsa-sha2-256",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "ecdsa-sha2-nistp256-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsEcdsaP384) {
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521",
      "rsa-sha2-512",
      "rsa-sha2-256",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "ecdsa-sha2-nistp384-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsEcdsaP521) {
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "ecdsa-sha2-nistp521",
      "rsa-sha2-512",
      "rsa-sha2-256",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "ecdsa-sha2-nistp521-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsRsaSha512) {
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "rsa-sha2-512",
      "rsa-sha2-256",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "rsa-sha2-512-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsRsaSha256) {
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "rsa-sha2-256",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "rsa-sha2-256-cert-v01@openssh.com");
}

TEST_F(UpstreamUserAuthServiceTest, OnServiceAcceptedServerSigAlgsUnsupported) {
  // If the server-sig-algs extension is present but there is no overlap with
  // our supported key types, we'll still attempt to authenticate with the
  // default key type.
  peer_ext_info_ = wire::ExtInfoMsg{};
  peer_ext_info_->extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = string_list{
      "sk-ssh-ed25519@openssh.com",
      "sk-ssh-ed25519-cert-v01@openssh.com",
      "sk-ecdsa-sha2-nistp256@openssh.com",
      "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
      "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
      "ssh-dss",
      "ssh-dss-cert-v01@openssh.com",
      "ssh-rsa",
    },
  });

  auto session_id = "SESSION-ID"_bytes;
  EXPECT_CALL(*transport_, sessionId()).WillOnce(ReturnRef(session_id));

  wire::Message req;
  triggerUserAuthRequestMsg(&req);

  verifySignature(session_id, req, "ssh-ed25519-cert-v01@openssh.com");
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

  EXPECT_CALL(*transport_, updatePeerExtInfo(Eq(ext_info)));

  auto r = service_->handleMessage(wire::Message{ext_info});
  ASSERT_OK(r);

  // It is an error to receive multiple ExtInfo messages during the same auth exchange.
  r = service_->handleMessage(wire::Message{ext_info});
  ASSERT_EQ(absl::FailedPreconditionError("unexpected ExtInfoMsg received"), r);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthSuccessNoPeerExtInfo) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  // We need to first call onServiceAccepted() to initialize some internal state.
  AuthState state;
  state.allow_response = std::make_unique<pomerium::extensions::ssh::AllowResponse>();
  state.allow_response->set_username("example-username");
  EXPECT_CALL(*transport_, authState())
    .WillRepeatedly(ReturnRef(state));
  auto streamId = "stream-id"_bytes;
  EXPECT_CALL(*transport_, sessionId())
    .WillOnce(ReturnRef(streamId));
  EXPECT_CALL(*transport_, sendMessageToConnection(MSG(wire::UserAuthRequestMsg, _)))
    .WillOnce(Return(123));
  ASSERT_OK(service_->onServiceAccepted());

  wire::Message msg{wire::UserAuthSuccessMsg{}};

  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(std::nullopt));

  EXPECT_CALL(*transport_, forward(Eq(msg), Eq(FrameTags::EffectiveHeader)));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);

  EXPECT_EQ(0, d.dispatch_.size());
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthSuccessWithPeerExtInfo) {
  TestSshMessageDispatcher d;
  service_->registerMessageHandlers(d);

  // We need to first call onServiceAccepted() to initialize some internal state.
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
  ASSERT_OK(service_->onServiceAccepted());

  wire::Message msg{wire::UserAuthSuccessMsg{}};

  wire::ExtInfoMsg ext_info{};
  wire::test::populateFields(ext_info);
  EXPECT_CALL(*transport_, peerExtInfo())
    .WillOnce(Return(std::make_optional(ext_info)));

  EXPECT_CALL(*transport_, forward(Eq(msg), Eq(FrameTags::EffectiveHeader)));

  auto r = service_->handleMessage(std::move(msg));
  ASSERT_OK(r);
  ASSERT_EQ(ext_info, state.upstream_ext_info);

  EXPECT_EQ(0, d.dispatch_.size());
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthSuccessOutOfOrder) {
  // We don't expect a UserAuthSuccessMsg before sending an auth request.
  auto r = service_->handleMessage(wire::Message{wire::UserAuthSuccessMsg{}});
  ASSERT_EQ(absl::FailedPreconditionError("unexpected UserAuthSuccessMsg received"), r);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageAuthFailure) {
  wire::UserAuthFailureMsg msg{};
  auto r = service_->handleMessage(wire::Message{msg});
  ASSERT_EQ(absl::PermissionDeniedError(""), r);
}

TEST_F(UpstreamUserAuthServiceTest, HandleMessageUnknownType) {
  auto r = service_->handleMessage(wire::Message{wire::DebugMsg{}});
  ASSERT_EQ(absl::InternalError("received unexpected message of type Debug (4)"), r);
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec