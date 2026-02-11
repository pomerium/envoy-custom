#include "source/common/span.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "gtest/gtest.h"
#include <unistd.h>
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "test/test_common/test_common.h"
#include "test/test_common/environment.h"
#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/logging.h"

#pragma clang unsafe_buffer_usage begin
#include "absl/strings/str_split.h"
#include "absl/strings/str_replace.h"
#pragma clang unsafe_buffer_usage end

extern "C" {
#include "openssh/ssh2.h"
#include "openssh/authfile.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
}

namespace openssh::test {

using Envoy::Extensions::NetworkFilters::GenericProxy::Codec::test::copyTestdataToWritableTmp;

TEST(OpensshTest, StatusFromErr) {
  EXPECT_EQ(absl::OkStatus(), statusFromErr(0));
  for (int i = -1; i >= -60; i--) {
    auto stat = statusFromErr(i);
    // testing each individual status code is not very helpful, but we can make sure that the
    // status codes are within the expected values
    EXPECT_THAT(stat.code(), AnyOf(Eq(absl::StatusCode::kInternal),
                                   Eq(absl::StatusCode::kResourceExhausted),
                                   Eq(absl::StatusCode::kInvalidArgument),
                                   Eq(absl::StatusCode::kPermissionDenied),
                                   Eq(absl::StatusCode::kUnavailable),
                                   Eq(absl::StatusCode::kCancelled),
                                   Eq(absl::StatusCode::kFailedPrecondition),
                                   Eq(absl::StatusCode::kAborted),
                                   Eq(absl::StatusCode::kNotFound),
                                   Eq(absl::StatusCode::kDeadlineExceeded),
                                   Eq(absl::StatusCode::kUnimplemented)));
    EXPECT_EQ(stat.message(), std::string_view(ssh_err(i)));
  }
  EXPECT_EQ(absl::UnknownError("unknown error"), statusFromErr(-61));
}

TEST(OpensshTest, DisconnectCodeToString) {
#define CHECK_FORMAT_(NAME) EXPECT_EQ(disconnectCodeToString(NAME), absl::AsciiStrToLower(absl::StrReplaceAll(absl::StripPrefix(#NAME, "SSH2_DISCONNECT_"), {{"_", " "}})));
  CHECK_FORMAT_(SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT);
  CHECK_FORMAT_(SSH2_DISCONNECT_PROTOCOL_ERROR);
  CHECK_FORMAT_(SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
  CHECK_FORMAT_(SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED);
  CHECK_FORMAT_(SSH2_DISCONNECT_MAC_ERROR);
  CHECK_FORMAT_(SSH2_DISCONNECT_COMPRESSION_ERROR);
  CHECK_FORMAT_(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE);
  CHECK_FORMAT_(SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
  CHECK_FORMAT_(SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
  CHECK_FORMAT_(SSH2_DISCONNECT_CONNECTION_LOST);
  CHECK_FORMAT_(SSH2_DISCONNECT_BY_APPLICATION);
  CHECK_FORMAT_(SSH2_DISCONNECT_TOO_MANY_CONNECTIONS);
  CHECK_FORMAT_(SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
  CHECK_FORMAT_(SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
  CHECK_FORMAT_(SSH2_DISCONNECT_ILLEGAL_USER_NAME);
  EXPECT_EQ("(unknown)", disconnectCodeToString(123456));
#undef CHECK_FORMAT_
}
TEST(OpensshTest, StatusCodeToDisconnectCode) {
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kNotFound));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kAlreadyExists));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kPermissionDenied));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kFailedPrecondition));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kAborted));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(SSH2_DISCONNECT_PROTOCOL_ERROR, statusCodeToDisconnectCode(absl::StatusCode::kUnauthenticated));
  EXPECT_EQ(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, statusCodeToDisconnectCode(absl::StatusCode::kResourceExhausted));
  EXPECT_EQ(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, statusCodeToDisconnectCode(absl::StatusCode::kUnimplemented));
  EXPECT_EQ(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, statusCodeToDisconnectCode(absl::StatusCode::kInternal));
  EXPECT_EQ(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, statusCodeToDisconnectCode(absl::StatusCode::kUnavailable));
  EXPECT_EQ(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, statusCodeToDisconnectCode(absl::StatusCode::kDataLoss));
  EXPECT_EQ(SSH2_DISCONNECT_BY_APPLICATION, statusCodeToDisconnectCode(absl::StatusCode::kCancelled));
  EXPECT_EQ(SSH2_DISCONNECT_BY_APPLICATION, statusCodeToDisconnectCode(absl::StatusCode::kDeadlineExceeded));

  EXPECT_EQ(SSH2_DISCONNECT_BY_APPLICATION, statusCodeToDisconnectCode(absl::OkStatus().code()));
  EXPECT_EQ(SSH2_DISCONNECT_BY_APPLICATION, statusCodeToDisconnectCode(absl::UnknownError("").code()));
#if !__has_feature(address_sanitizer)
  EXPECT_EQ(SSH2_DISCONNECT_BY_APPLICATION, statusCodeToDisconnectCode(absl::StatusCode(-10)));
#endif
}

TEST(SSHKeyTest, FromPrivateKeyFilePath) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    auto r = SSHKey::fromPrivateKeyFile(privKeyPath);
    ASSERT_OK(r.status());
  }
}

TEST(SSHKeyTest, FromPrivateKeyFilePath_BadPermissions) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    for (auto mode : {0640, 0644, 0666}) {
      auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), mode);
      auto r = SSHKey::fromPrivateKeyFile(privKeyPath);
      ASSERT_EQ(absl::InvalidArgumentError("bad permissions"), r.status());
    }
  }
}

TEST(SSHKeyTest, FromPrivateKeyBytes) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    auto fromFile = SSHKey::fromPrivateKeyFile(privKeyPath);
    ASSERT_OK(fromFile.status());
    auto privKeyStr = Envoy::TestEnvironment::readFileToStringForTest(privKeyPath);
    auto fromBytes = SSHKey::fromPrivateKeyBytes(privKeyStr);
    ASSERT_OK(fromBytes.status());
    std::string privKeyBase64Str;
    absl::Base64Escape(privKeyStr, &privKeyBase64Str);
    auto fromBase64 = SSHKey::fromPrivateKeyBytes(privKeyBase64Str);
    ASSERT_EQ(**fromFile, **fromBytes);
    ASSERT_EQ(**fromFile, **fromBase64);
    if (keyName != "ed25519_1"sv) {
      // ed25519 keys can only be formatted as SSHKEY_PRIVATE_OPENSSH, which is non-deterministic
      auto formattedFromFile = (*fromFile)->formatPrivateKey(SSHKEY_PRIVATE_PEM);
      auto formattedFromBytes = (*fromBytes)->formatPrivateKey(SSHKEY_PRIVATE_PEM);
      auto formattedFromBytesBase64 = (*fromBytes)->formatPrivateKey(SSHKEY_PRIVATE_PEM, true);
      ASSERT_OK(formattedFromFile.status());
      ASSERT_OK(formattedFromBytes.status());
      ASSERT_OK(formattedFromBytesBase64.status());
      ASSERT_EQ(*formattedFromFile, *formattedFromBytes);
      ASSERT_EQ(privKeyBase64Str, *formattedFromBytesBase64);
    }
  }
}

TEST(SSHKeyTest, FromPrivateKeyBytes_InvalidData) {
  auto fromBytes = SSHKey::fromPrivateKeyBytes("not a ssh private key"s);
  ASSERT_EQ(absl::InvalidArgumentError("invalid format"), fromBytes.status());
}

TEST(SSHKeyTest, FromPrivateKeyBytes_EmptyData) {
  auto fromBytes = SSHKey::fromPrivateKeyBytes("");
  ASSERT_EQ(absl::InvalidArgumentError("invalid format"), fromBytes.status());
}

TEST(SSHKeyTest, FromPrivateKeyBytes_InvalidBase64Data) {
  auto fromBytes = SSHKey::fromPrivateKeyBytes("LS0tLS1Cnot base64"s);
  ASSERT_EQ(absl::InvalidArgumentError("invalid base64"), fromBytes.status());
}

TEST(SSHKeyTest, FromPrivateKeyBytes_InvalidPublicKeyData) {
  auto key = *SSHKey::generate(KEY_RSA, 2048);
  ASSERT_EQ(absl::InvalidArgumentError("invalid format"), SSHKey::fromPrivateKeyBytes(key->formatPublicKey()).status());
}

TEST(SSHKeyTest, FromPrivateKeyDataSource) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    auto privKeyBytes = Envoy::TestEnvironment::readFileToStringForTest(privKeyPath);
    auto expected = *SSHKey::fromPrivateKeyFile(privKeyPath);

    corev3::DataSource filepathDataSource;
    *filepathDataSource.mutable_filename() = privKeyPath;

    corev3::DataSource inlineBytesDataSource;
    *inlineBytesDataSource.mutable_inline_bytes() = privKeyBytes;

    corev3::DataSource inlineStringDataSource;
    *inlineStringDataSource.mutable_inline_string() = privKeyBytes;

    for (const auto& dataSource : {
           filepathDataSource,
           inlineBytesDataSource,
           inlineStringDataSource,
         }) {
      auto key = SSHKey::fromPrivateKeyDataSource(dataSource);
      ASSERT_OK(key.status());
      ASSERT_EQ(*expected, **key);
    }
  }
}

TEST(SSHKeyTest, FromPrivateKeyDataSource_UnsupportedEnv) {
  corev3::DataSource envDataSource;
  *envDataSource.mutable_environment_variable() = "foo";
  auto key = SSHKey::fromPrivateKeyDataSource(envDataSource);
  ASSERT_EQ(absl::UnimplementedError("environment variable data source not supported"), key.status());
}

TEST(SSHKeyTest, FromPrivateKeyDataSource_Empty) {
  corev3::DataSource emptyDataSource;
  auto key = SSHKey::fromPrivateKeyDataSource(emptyDataSource);
  ASSERT_EQ(absl::InvalidArgumentError("data source is empty"), key.status());
}

TEST(SSHKeyTest, FromToPublicKeyBlob) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    copyTestdataToWritableTmp(fmt::format("regress/unittests/sshkey/testdata/{}.pub", keyName), 0644);
    auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    auto priv = *SSHKey::fromPrivateKeyFile(privKeyPath);
    auto our_blob = priv->toPublicKeyBlob();

    const auto rsa1Pub = privKeyPath + ".pub";
    detail::sshkey_ptr openssh_pubkey;
    ASSERT_EQ(0, sshkey_load_public(rsa1Pub.c_str(), std::out_ptr(openssh_pubkey), nullptr));
    CBytesPtr blob_ptr{};
    size_t blob_len{};
    ASSERT_EQ(0, sshkey_to_blob(openssh_pubkey.get(), std::out_ptr(blob_ptr), &blob_len));
    ASSERT_EQ(to_bytes(unsafe_forge_span(blob_ptr.get(), blob_len)), our_blob);

    auto our_pubkey = *SSHKey::fromPublicKeyBlob(our_blob);
    ASSERT_EQ(1, sshkey_equal(our_pubkey->sshkeyForTest(), openssh_pubkey.get()));
  }
}

TEST(SSHKeyTest, FromPublicKeyBlob_Invalid) {
  auto r = SSHKey::fromPublicKeyBlob(bytes{'i', 'n', 'v', 'a', 'l', 'i', 'd'});
  EXPECT_EQ(absl::InvalidArgumentError("invalid format"), r.status());
}

TEST(SSHKeyTest, FromPublicKeyBlob_Empty) {
  auto r = SSHKey::fromPublicKeyBlob({});
  EXPECT_EQ(absl::InvalidArgumentError("invalid format"), r.status());
}

TEST(SSHKeyTest, ToPrivateKeyPem) {
  for (auto [keyName, format] : {
         std::tuple{"rsa_1"s, SSHKEY_PRIVATE_PEM},
         std::tuple{"ecdsa_1"s, SSHKEY_PRIVATE_PEM},
         std::tuple{"ed25519_1"s, SSHKEY_PRIVATE_OPENSSH}}) {
    auto relPath = absl::StrCat("regress/unittests/sshkey/testdata/", keyName);
    auto privKeyPath = copyTestdataToWritableTmp(relPath, 0600);
    auto priv = *SSHKey::fromPrivateKeyFile(privKeyPath);
    auto ours = *priv->formatPrivateKey(format);
    auto newPath = privKeyPath + "_2";

    if (format == SSHKEY_PRIVATE_OPENSSH) {
      // the openssh key format contains random bytes, so we can't check that the serialized form
      // of the key is identical to the original, but we can read it again and compare the actual
      // keys, which will not change.
      //
      // for reference (see sshkey_private_to_fileblob):
      // SSHKEY_PRIVATE_OPENSSH uses sshkey_private_to_blob2
      // SSHKEY_PRIVATE_PEM/PKCS8 uses sshkey_private_to_blob_pem_pkcs8
      ASSERT_NE(ours, *priv->formatPrivateKey(format)); // sanity check
    } else {
      ASSERT_EQ(ours, *priv->formatPrivateKey(format)); // sanity check
    }

    Envoy::TestEnvironment::writeStringToFileForTest(newPath, ours, true);
    chmod(newPath.c_str(), 0600);
    auto priv2 = *SSHKey::fromPrivateKeyFile(newPath);
    ASSERT_EQ(*priv, *priv2);
  }
}

TEST(SSHKeyTest, ToPublicKeyPem) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    auto relPath = absl::StrCat("regress/unittests/sshkey/testdata/", keyName);
    auto privKeyPath = copyTestdataToWritableTmp(relPath, 0600);
    auto priv = *SSHKey::fromPrivateKeyFile(privKeyPath);
    auto ours = priv->formatPublicKey();

    const std::string runfilePath = Envoy::TestEnvironment::runfilesPath(absl::StrCat(relPath, ".pub"), "openssh_portable");
    auto golden = Envoy::TestEnvironment::readFileToStringForTest(runfilePath);

    std::vector<std::string> parts = absl::StrSplit(golden, ' ');
    EXPECT_EQ(fmt::format("{} {}", parts[0], parts[1]), ours); // don't include comment
  }
}

TEST(SSHKeyTest, Generate) {
  auto r = SSHKey::generate(KEY_RSA, 2048);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_RSA, (*r)->keyType());

  r = SSHKey::generate(KEY_ECDSA, 256);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_ECDSA, (*r)->keyType());

  r = SSHKey::generate(KEY_ECDSA, 384);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_ECDSA, (*r)->keyType());

  r = SSHKey::generate(KEY_ECDSA, 521);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_ECDSA, (*r)->keyType());

  r = SSHKey::generate(KEY_ED25519, 256);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_ED25519, (*r)->keyType());

  r = SSHKey::generate(KEY_RSA, 256);
  EXPECT_EQ(absl::InvalidArgumentError("Invalid key length"), r.status());
}

class SSHKeyTestSuite : public testing::TestWithParam<std::tuple<sshkey_types, uint32_t>> {
public:
  SSHKeyPtr generate() const {
    return *std::apply(&SSHKey::generate, GetParam());
  }
  // generates a key with some algorithm that isn't the current one
  SSHKeyPtr generateWithDifferentAlgorithm() const {
    switch (auto [alg, _] = GetParam(); alg) {
    case KEY_RSA:
      return *SSHKey::generate(KEY_ECDSA, 256);
    case KEY_ECDSA:
      return *SSHKey::generate(KEY_ED25519, 256);
    case KEY_ED25519:
      return *SSHKey::generate(KEY_RSA, 2048);
    default:
      PANIC("invalid test case");
    }
  }
};

TEST_P(SSHKeyTestSuite, Compare) {
  auto key1 = generate();
  auto key2 = generate();
  EXPECT_EQ(*key1, *key1);
  EXPECT_EQ(*key2, *key2);
  EXPECT_NE(*key1, *key2);
  EXPECT_EQ(*key1->toPublicKey(), *key1);
  EXPECT_NE(*key2->toPublicKey(), *key1);
  EXPECT_EQ(*key1->toPublicKey(), *key1->toPublicKey());
  EXPECT_NE(*key2->toPublicKey(), *key1->toPublicKey());
}

TEST_P(SSHKeyTestSuite, SignVerify) {
  auto key1 = generate();
  auto key2 = generate();

  auto key1_pub = key1->toPublicKey();
  auto key2_pub = key2->toPublicKey();

  bytes payload{'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z'};
  {
    auto sig = *key1->sign(payload);
    ASSERT_OK(key1->verify(sig, payload));
    ASSERT_OK(key1_pub->verify(sig, payload));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"), key2->verify(sig, payload));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"), key2_pub->verify(sig, payload));
  }

  {
    auto sig = *key2->sign(payload);
    ASSERT_OK(key2->verify(sig, payload));
    ASSERT_OK(key2_pub->verify(sig, payload));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"), key1->verify(sig, payload));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"), key1_pub->verify(sig, payload));
  }

  // the exact error we get from openssh depends on the key algorithm; it will be one of these two
  ASSERT_THAT(key1_pub->sign(payload).status(), AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                                                      Eq(absl::InternalError("error in libcrypto"))));
  ASSERT_THAT(key2_pub->sign(payload).status(), AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                                                      Eq(absl::InternalError("error in libcrypto"))));
}

INSTANTIATE_TEST_SUITE_P(SSHKeyTest, SSHKeyTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<sshkey_types, uint32_t>>{
                           {KEY_RSA, 2048},
                           {KEY_ECDSA, 256},
                           {KEY_ECDSA, 384},
                           {KEY_ECDSA, 521},
                           {KEY_ED25519, 256},
                         }));

TEST(SSHKeyTest, SignWithDifferentAlgorithms) {
  auto key = *SSHKey::generate(KEY_RSA, 2048);
  auto key_pub = key->toPublicKey();

  bytes payload = "foobarbaz"_bytes;
  {
    auto sig = key->sign(payload, "rsa-sha2-256");
    ASSERT_OK(sig.status());
    ASSERT_OK(key->verify(*sig, payload));
    ASSERT_OK(key_pub->verify(*sig, payload));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"),
              key->verify(*sig, payload, "rsa-sha2-512"));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"),
              key_pub->verify(*sig, payload, "rsa-sha2-512"));
  }

  {
    auto sig = key->sign(payload, "rsa-sha2-512");
    ASSERT_OK(sig.status());
    ASSERT_OK(key->verify(*sig, payload));
    ASSERT_OK(key_pub->verify(*sig, payload));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"),
              key->verify(*sig, payload, "rsa-sha2-256"));
    ASSERT_EQ(absl::PermissionDeniedError("incorrect signature"),
              key_pub->verify(*sig, payload, "rsa-sha2-256"));
  }
}

TEST(SSHKeyTest, CertSigningAlgorithmToPlain) {
  ASSERT_EQ(std::optional{"ssh-ed25519"},
            certSigningAlgorithmToPlain("ssh-ed25519-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"sk-ssh-ed25519@openssh.com"},
            certSigningAlgorithmToPlain("sk-ssh-ed25519-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"ecdsa-sha2-nistp256"},
            certSigningAlgorithmToPlain("ecdsa-sha2-nistp256-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"ecdsa-sha2-nistp384"},
            certSigningAlgorithmToPlain("ecdsa-sha2-nistp384-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"ecdsa-sha2-nistp521"},
            certSigningAlgorithmToPlain("ecdsa-sha2-nistp521-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"sk-ecdsa-sha2-nistp256@openssh.com"},
            certSigningAlgorithmToPlain("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"rsa-sha2-512"},
            certSigningAlgorithmToPlain("rsa-sha2-512-cert-v01@openssh.com"));
  ASSERT_EQ(std::optional{"rsa-sha2-256"},
            certSigningAlgorithmToPlain("rsa-sha2-256-cert-v01@openssh.com"));

  // not supported
  ASSERT_EQ(std::nullopt, certSigningAlgorithmToPlain("ssh-dss-cert-v01@openssh.com"));

  // unknown
  ASSERT_EQ(std::nullopt, certSigningAlgorithmToPlain(""));
}

class SSHKeyCertTestSuite : public SSHKeyTestSuite {
public:
  void SetUp() override {
    key_ = generate();
    signer_ = generate();
  }
  SSHKeyPtr key_;
  SSHKeyPtr signer_;
};

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate) {
  auto [keyType, _] = GetParam();
  auto sigAlgs = absl::StrJoin(key_->signatureAlgorithmsForKeyType(), ",");
  auto stat = key_->convertToSignedUserCertificate(1, {"principal1", "principal2"}, {"extension1", "extension2"}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  ASSERT_OK(stat);
  EXPECT_EQ(keyType + 3, key_->keyType()); // for the algorithms we use here, this is fine.
                                           // the openssh type converter function isn't public
  const auto* key = key_->sshkeyForTest();
  EXPECT_TRUE(sshkey_is_cert(key));
  EXPECT_TRUE(sshkey_check_cert_sigtype(key, sigAlgs.c_str()) == 0);

  EXPECT_STREQ("user", sshkey_cert_type(key));

  bytes payload = {'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z'};
  auto sig = key_->sign(payload);
  ASSERT_OK(sig.status());

  auto pubKey = key_->toPublicKey();
  ASSERT_OK(pubKey->verify(*sig, payload));
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_DifferentSignerAlgorithm) {
  // openssh PROTOCOL.certkeys states:
  //  Note that it is possible for a RSA certificate key to be signed by a
  //  Ed25519 or ECDSA CA key and vice-versa.
  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1),
                                                   *generateWithDifferentAlgorithm());
  ASSERT_OK(stat);
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_SignerIsCert) {
  // openssh PROTOCOL.certkeys states:
  //  "Chained" certificates, where the signature key type is a certificate type itself are
  //  NOT supported.

  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  ASSERT_OK(stat);

  auto key2 = generate();
  auto stat2 = key2->convertToSignedUserCertificate(2, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *key_);
  ASSERT_EQ(absl::InvalidArgumentError("invalid certificate signing key"), stat2);
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_AlreadyCert) {
  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  ASSERT_OK(stat);
  stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  // the exact error we get from openssh depends on the key algorithm; it will be one of these two
  ASSERT_THAT(stat, AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                          Eq(absl::InternalError("error in libcrypto"))));
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_KeyIsPublicKey) {
  auto key = generate();
  auto pub = key->toPublicKey();
  auto stat = pub->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  // this is fine, the cert just won't be able to sign etc.
  ASSERT_OK(stat);
  ASSERT_THAT(pub->sign(bytes{'f', 'o', 'o'}).status(), AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                                                              Eq(absl::InternalError("error in libcrypto"))));
  ASSERT_EQ(absl::InvalidArgumentError("unknown or unsupported key type"), pub->formatPrivateKey().status());
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_SignerIsPublicKey) {
  auto key = generate();
  auto pub = key->toPublicKey();
  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *pub);
  ASSERT_THAT(stat, AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                          Eq(absl::InternalError("error in libcrypto"))));
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_TooManyPrincipals) {
  std::vector<std::string> principals(SSHKEY_CERT_MAX_PRINCIPALS + 1, "asdf");
  auto stat = key_->convertToSignedUserCertificate(1, principals, {}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  ASSERT_EQ(absl::InvalidArgumentError("number of principals (257) is more than the maximum allowed (256)"), stat);
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_BadTimestamps) {
  { // start time > end time
    auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Now() + absl::Hours(1), absl::Now(), *signer_);
    ASSERT_EQ(absl::InvalidArgumentError("valid_start_time >= valid_end_time"), stat);
  }
  { // start time == end time
    auto now = absl::Now();
    auto stat = key_->convertToSignedUserCertificate(1, {}, {}, now, now, *signer_);
    ASSERT_EQ(absl::InvalidArgumentError("valid_start_time >= valid_end_time"), stat);
  }
}

TEST_P(SSHKeyCertTestSuite, Compare) {
  auto stat = key_->convertToSignedUserCertificate(1, {"principal1", "principal2"}, {"extension1", "extension2"}, absl::Now(), absl::Now() + absl::Hours(1), *signer_);
  EXPECT_EQ(*key_, *key_);
  EXPECT_EQ(*key_, *key_->toPublicKey());
}

INSTANTIATE_TEST_SUITE_P(SSHKeyCertTest, SSHKeyCertTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<sshkey_types, uint32_t>>{
                           {KEY_RSA, 2048},
                           {KEY_ECDSA, 256},
                           {KEY_ECDSA, 384},
                           {KEY_ECDSA, 521},
                           {KEY_ED25519, 256},
                         }));

class SSHKeyPropertiesTestSuite : public SSHKeyTestSuite {
public:
  void SetUp() override {
    auto [keyType, bits] = GetParam();
    auto r = SSHKey::generate(SSHKey::keyTypePlain(keyType), bits);
    ASSERT_OK(r.status());
    if (SSHKey::keyTypeIsCert(keyType)) {
      signer_ = *SSHKey::generate(SSHKey::keyTypePlain(keyType), bits);
      ASSERT_OK((*r)->convertToSignedUserCertificate(1, {}, {}, absl::Now(), absl::Now() + absl::Hours(1), *signer_));
    }
    key_ = std::move(r).value();
  }

  SSHKeyPtr key_;
  SSHKeyPtr signer_; // non-null if key is a cert type
};

TEST_P(SSHKeyPropertiesTestSuite, Fingerprint) {
  const auto* raw_key = key_->sshkeyForTest();
  CStringPtr expected{sshkey_fingerprint(raw_key, SSH_DIGEST_SHA256, SSH_FP_DEFAULT)};
  ASSERT_NE(nullptr, expected);
  auto r = key_->fingerprint(SSH_FP_DEFAULT);
  EXPECT_OK(r.status());
  EXPECT_EQ(std::string_view(expected.get()), std::string_view(*r));
}

TEST_P(SSHKeyPropertiesTestSuite, Fingerprint_InvalidFormat) {
#if __has_feature(address_sanitizer)
  // asan doesn't like the enum being out of range
  GTEST_SKIP() << "disabled for asan builds";
#endif
  const auto* raw_key = key_->sshkeyForTest();
  auto expected = sshkey_fingerprint(raw_key, SSH_DIGEST_SHA256, sshkey_fp_rep(100));
  ASSERT_EQ(nullptr, expected); // sanity check
  auto r = key_->fingerprint(sshkey_fp_rep(100));
  EXPECT_EQ(absl::InvalidArgumentError("sshkey_fingerprint failed"), r.status());
}

TEST_P(SSHKeyPropertiesTestSuite, RawFingerprint) {
  const auto* raw_key = key_->sshkeyForTest();
  CBytesPtr fp_bytes;
  size_t fp_size{};
  sshkey_fingerprint_raw(raw_key, SSH_DIGEST_SHA256, std::out_ptr(fp_bytes), &fp_size);
  auto expected_fp = to_bytes(unsafe_forge_span(fp_bytes.get(), fp_size));

  CStringPtr hex{sshkey_fingerprint(raw_key, SSH_DIGEST_SHA256, SSH_FP_HEX)};
  std::string plainHexString = absl::StrReplaceAll(absl::StripPrefix(std::string_view(hex.get()), "SHA256"), {{":", ""}});
  std::string fpDecodedFromHex;
  ASSERT_TRUE(absl::HexStringToBytes(plainHexString, &fpDecodedFromHex));

  auto r = key_->rawFingerprint();
  EXPECT_EQ(expected_fp, r);
  EXPECT_EQ(to_bytes(fpDecodedFromHex), r);
}

TEST_P(SSHKeyPropertiesTestSuite, KeyTypeName) {
  auto [keyType, bits] = GetParam();
  const std::string_view expected = sshkey_ssh_name(key_->sshkeyForTest());
  const std::string_view actual = key_->keyTypeName();
  ASSERT_NE(nullptr, actual.data());

  switch (keyType) {
  case KEY_RSA:
    ASSERT_EQ("ssh-rsa", expected);
    break;
  case KEY_RSA_CERT:
    ASSERT_EQ("ssh-rsa-cert-v01@openssh.com", expected);
    break;
  case KEY_ECDSA:
    switch (bits) {
    case 256:
      ASSERT_EQ("ecdsa-sha2-nistp256", expected);
      break;
    case 384:
      ASSERT_EQ("ecdsa-sha2-nistp384", expected);
      break;
    case 521:
      ASSERT_EQ("ecdsa-sha2-nistp521", expected);
      break;
    default:
      FAIL() << "invalid test case";
    }
    break;
  case KEY_ECDSA_CERT:
    switch (bits) {
    case 256:
      ASSERT_EQ("ecdsa-sha2-nistp256-cert-v01@openssh.com", expected);
      break;
    case 384:
      ASSERT_EQ("ecdsa-sha2-nistp384-cert-v01@openssh.com", expected);
      break;
    case 521:
      ASSERT_EQ("ecdsa-sha2-nistp521-cert-v01@openssh.com", expected);
      break;
    default:
      FAIL() << "invalid test case";
    }
    break;
  case KEY_ED25519:
    ASSERT_EQ("ssh-ed25519", expected);
    break;
  case KEY_ED25519_CERT:
    ASSERT_EQ("ssh-ed25519-cert-v01@openssh.com", expected);
    break;
  default:
    FAIL() << "invalid test case";
  }
  ASSERT_EQ(reinterpret_cast<uintptr_t>(expected.data()),
            reinterpret_cast<uintptr_t>(actual.data()));            // pointers should match
  ASSERT_EQ(SSHKey::keyTypeFromName(std::string(actual)), keyType); // sanity check
}

TEST_P(SSHKeyPropertiesTestSuite, KeyType) {
  auto [keyType, _] = GetParam();
  EXPECT_EQ(keyType, key_->keyType());
}

TEST_P(SSHKeyPropertiesTestSuite, SignatureAlgorithmsForKeyType) {
  auto [keyType, bits] = GetParam();
  switch (keyType) {
  case KEY_RSA: {
    auto expected = std::vector<std::string>{"rsa-sha2-256", "rsa-sha2-512"};
    EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
  } break;
  case KEY_RSA_CERT: {
    auto expected = std::vector<std::string>{"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com"};
    EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
  } break;
  case KEY_ECDSA:
    switch (bits) {
    case 256: {
      auto expected = std::vector<std::string>{"ecdsa-sha2-nistp256"};
    } break;
    case 384: {
      auto expected = std::vector<std::string>{"ecdsa-sha2-nistp384"};
      EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
    } break;
    case 521: {
      auto expected = std::vector<std::string>{"ecdsa-sha2-nistp521"};
      EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
    } break;
    default:
      FAIL() << "invalid test case";
    }
    break;
  case KEY_ECDSA_CERT:
    switch (bits) {
    case 256: {
      auto expected = std::vector<std::string>{"ecdsa-sha2-nistp256-cert-v01@openssh.com"};
      EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
    } break;
    case 384: {
      auto expected = std::vector<std::string>{"ecdsa-sha2-nistp384-cert-v01@openssh.com"};
      EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
    } break;
    case 521: {
      auto expected = std::vector<std::string>{"ecdsa-sha2-nistp521-cert-v01@openssh.com"};
      EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
    } break;
    default:
      FAIL() << "invalid test case";
    }
    break;
  case KEY_ED25519: {
    auto expected = std::vector<std::string>{"ssh-ed25519"};
    EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
  } break;
  case KEY_ED25519_CERT: {
    auto expected = std::vector<std::string>{"ssh-ed25519-cert-v01@openssh.com"};
    EXPECT_EQ(expected, key_->signatureAlgorithmsForKeyType());
  } break;
  default:
    FAIL() << "invalid test case";
  }
}

TEST_P(SSHKeyPropertiesTestSuite, KeyTypePlain) {
  auto [keyType, _] = GetParam();
  sshkey_types expected{};
  switch (keyType) {
  case KEY_RSA:
    expected = KEY_RSA;
    break;
  case KEY_RSA_CERT:
    expected = KEY_RSA;
    break;
  case KEY_ECDSA:
    expected = KEY_ECDSA;
    break;
  case KEY_ECDSA_CERT:
    expected = KEY_ECDSA;
    break;
  case KEY_ED25519:
    expected = KEY_ED25519;
    break;
  case KEY_ED25519_CERT:
    expected = KEY_ED25519;
    break;
  default:
    FAIL() << "invalid test case";
  }
  EXPECT_EQ(expected, key_->keyTypePlain());
}

INSTANTIATE_TEST_SUITE_P(SSHKeyPropertiesTest, SSHKeyPropertiesTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<sshkey_types, uint32_t>>{
                           {KEY_RSA, 2048},
                           {KEY_RSA_CERT, 2048},
                           {KEY_ECDSA, 256},
                           {KEY_ECDSA_CERT, 256},
                           {KEY_ECDSA, 384},
                           {KEY_ECDSA_CERT, 384},
                           {KEY_ECDSA, 521},
                           {KEY_ECDSA_CERT, 521},
                           {KEY_ED25519, 256},
                           {KEY_ED25519_CERT, 256},
                         }));

TEST(OpensshTest, LoadHostKeys) {
  std::vector<corev3::DataSource> sources;
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    auto filename = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    corev3::DataSource src;
    *src.mutable_filename() = filename;
    sources.push_back(std::move(src));
  }
  auto r = loadHostKeys(sources);
  ASSERT_OK(r.status());
  ASSERT_EQ(3, r->size());
}

TEST(OpensshTest, LoadHostKeys_DuplicateAlgorithm) {
  std::vector<corev3::DataSource> sources;
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1", "rsa_2"}) {
    auto filename = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    corev3::DataSource src;
    *src.mutable_filename() = filename;
    sources.push_back(std::move(src));
  }
  auto note = fmt::format("note: keys with algorithm ssh-rsa: {}, {}",
                          sources[0].filename(),
                          sources[3].filename());
  EXPECT_LOG_CONTAINS("error", note, {
    auto stat = loadHostKeys(sources);
    ASSERT_EQ(absl::InvalidArgumentError("host keys must have unique algorithms"), stat.status());
  });
}

TEST(OpensshTest, LoadHostKeysFromBytes_DuplicateAlgorithm) {
  EXPECT_LOG_CONTAINS("error", "note: keys with algorithm ssh-rsa: (key 0), (key 1)", {
    std::vector<corev3::DataSource> keys;
    corev3::DataSource ds1;
    *ds1.mutable_inline_string() = *(*openssh::SSHKey::generate(KEY_RSA, 2048))->formatPrivateKey();
    keys.push_back(std::move(ds1));
    corev3::DataSource ds2;
    *ds2.mutable_inline_string() = *(*openssh::SSHKey::generate(KEY_RSA, 2048))->formatPrivateKey();
    keys.push_back(std::move(ds2));

    auto stat = loadHostKeys(keys);
    ASSERT_EQ(absl::InvalidArgumentError("host keys must have unique algorithms"), stat.status());
  });
}

TEST(OpensshTest, LoadHostKeysFromBytes_InvalidInlineData) {
  for (bool use_bytes : {false, true}) {
    {
      std::vector<corev3::DataSource> keys;
      corev3::DataSource ds1;
      if (use_bytes) {
        *ds1.mutable_inline_bytes() = "not an ssh key";
      } else {
        *ds1.mutable_inline_string() = "not an ssh key";
      }
      keys.push_back(std::move(ds1));
      corev3::DataSource ds2;
      if (use_bytes) {
        *ds2.mutable_inline_bytes() = *(*openssh::SSHKey::generate(KEY_RSA, 2048))->formatPrivateKey();
      } else {
        *ds2.mutable_inline_string() = *(*openssh::SSHKey::generate(KEY_RSA, 2048))->formatPrivateKey();
      }
      keys.push_back(std::move(ds2));
      auto stat = loadHostKeys(keys);
      ASSERT_EQ(absl::InvalidArgumentError("error loading ssh host key [1/2] from inline data: invalid format"), stat.status());
    }
    {
      std::vector<corev3::DataSource> keys;
      corev3::DataSource ds1;
      if (use_bytes) {
        *ds1.mutable_inline_bytes() = *(*openssh::SSHKey::generate(KEY_RSA, 2048))->formatPrivateKey();
      } else {
        *ds1.mutable_inline_string() = *(*openssh::SSHKey::generate(KEY_RSA, 2048))->formatPrivateKey();
      }
      keys.push_back(std::move(ds1));
      corev3::DataSource ds2;
      if (use_bytes) {
        *ds2.mutable_inline_bytes() = "not an ssh key";
      } else {
        *ds2.mutable_inline_string() = "not an ssh key";
      }
      keys.push_back(std::move(ds2));
      auto stat = loadHostKeys(keys);
      ASSERT_EQ(absl::InvalidArgumentError("error loading ssh host key [2/2] from inline data: invalid format"), stat.status());
    }
  }
}

TEST(OpensshTest, LoadHostKeys_InvalidMode_Unreadable) {
  std::vector<corev3::DataSource> sources;
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1", "rsa_2"}) {
    // set invalid permissions on only one of the keys
    auto filename = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName),
                                              std::string_view(keyName) == "ecdsa_1" ? 0200 : 0600);
    corev3::DataSource src;
    *src.mutable_filename() = filename;
    sources.push_back(std::move(src));
  }
  if (getuid() == 0) {
    // For CI
    ASSERT_EQ(0, seteuid(1000));
    ASSERT_EQ(0, setegid(1000));
  }
  auto stat = loadHostKeys(sources);
  if (getuid() == 0) {
    ASSERT_EQ(0, seteuid(0));
    ASSERT_EQ(0, setegid(0));
  }
  ASSERT_EQ(absl::PermissionDeniedError(fmt::format("error loading ssh host key [2/4] from file {}: Permission denied",
                                                    sources.at(1).filename())),
            stat.status());
}

TEST(OpensshTest, LoadHostKeys_InvalidMode_TooOpen) {
  std::vector<corev3::DataSource> sources;
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1", "rsa_2"}) {
    // set invalid permissions on only one of the keys
    auto filename = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName),
                                              std::string_view(keyName) == "ecdsa_1" ? 0644 : 0600);

    corev3::DataSource src;
    *src.mutable_filename() = filename;
    sources.push_back(std::move(src));
  }
  auto stat = loadHostKeys(sources);
  ASSERT_EQ(absl::InvalidArgumentError(fmt::format("error loading ssh host key [2/4] from file {}: bad permissions",
                                                   sources.at(1).filename())),
            stat.status());
}

static const auto cipherInfo = std::unordered_map<std::string, std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>>{
  //             block_size, key_len, iv_len, auth_len
  {"aes128-ctr", {16, 16, 16, 0}},
  {"aes192-ctr", {16, 24, 16, 0}},
  {"aes256-ctr", {16, 32, 16, 0}},
  {"aes128-gcm@openssh.com", {16, 16, 12, 16}},
  {"aes256-gcm@openssh.com", {16, 32, 12, 16}},
  {"chacha20-poly1305@openssh.com", {8, 64, 0, 16}},
};

class SSHCipherTestSuite : public testing::TestWithParam<std::tuple<std::string, bytes, bytes>> {};

TEST_P(SSHCipherTestSuite, Init) {
  for (auto mode : {CipherMode::Read, CipherMode::Write}) {
    auto cipher = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{mode, 4}));
    auto [block_size, key_len, iv_len, auth_len] = cipherInfo.at(cipher.name());
    EXPECT_EQ(block_size, cipher.blockSize());
    EXPECT_EQ(key_len, cipher.keyLen());
    EXPECT_EQ(iv_len, cipher.ivLen());
    EXPECT_EQ(auth_len, cipher.authLen());
    EXPECT_EQ(4, cipher.aadLen());
  }
}

static const auto randomKexInitMsgs = [] {
  std::vector<wire::KexInitMsg> msgs(1000);
  for (int i = 0; i < 1000; i++) {
    wire::test::populateFields(msgs[i]);
  }
  return msgs;
}();

TEST_P(SSHCipherTestSuite, PacketLength) {
  auto cipher = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{CipherMode::Write, 4}));
  for (int i = 0; i < 1000; i++) {
    const wire::KexInitMsg& msg = randomKexInitMsgs[i];
    Envoy::Buffer::OwnedImpl plaintext;
    ASSERT_OK(wire::encodePacket(plaintext, msg, cipher.blockSize(), cipher.aadLen()).status());
    bytes packet;
    packet.resize(plaintext.length());
    plaintext.copyOut(0, packet.size(), packet.data());

    Envoy::Buffer::OwnedImpl ciphertext;
    ASSERT_OK(cipher.encryptPacket(i, ciphertext, plaintext));
    auto packetLen = cipher.packetLength(i, std::as_const(ciphertext));
    ASSERT_OK(packetLen.status());
    ASSERT_EQ(packet.size() - 4, *packetLen);
  }
}

TEST_P(SSHCipherTestSuite, PacketLength_PacketTooSmall) {
  auto reader = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{CipherMode::Read, 4}));
  Envoy::Buffer::OwnedImpl input;
  input.writeByte(0);
  input.writeByte(0);
  input.writeByte(0);
  EXPECT_EQ(absl::InvalidArgumentError("packet too small"), reader.packetLength(0, input).status());
}

TEST_P(SSHCipherTestSuite, RoundTrip) {
  auto reader = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{CipherMode::Read, 4}));
  auto writer = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{CipherMode::Write, 4}));

  for (int i = 0; i < 1000; i++) {
    const wire::KexInitMsg& msg = randomKexInitMsgs[i];
    Envoy::Buffer::OwnedImpl plaintext;
    ASSERT_OK(wire::encodePacket(plaintext, msg, writer.blockSize(), writer.aadLen()).status());
    auto packet_length = plaintext.peekBEInt<uint32_t>();
    bytes packet;
    packet.resize(plaintext.length());
    plaintext.copyOut(0, packet.size(), packet.data());

    Envoy::Buffer::OwnedImpl ciphertext;
    ASSERT_OK(writer.encryptPacket(i, ciphertext, plaintext));

    Envoy::Buffer::OwnedImpl decrypted;
    ASSERT_OK(reader.decryptPacket(i, decrypted, ciphertext, packet_length));
    wire::KexInitMsg msg2;
    ASSERT_OK(wire::decodePacket(decrypted, msg2).status());
    ASSERT_EQ(msg, msg2);
  }
}

INSTANTIATE_TEST_SUITE_P(SSHCipherTest, SSHCipherTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<std::string, bytes, bytes>>{
                           {"aes128-ctr", iv_bytes{}, randomBytes(16)},
                           {"aes192-ctr", iv_bytes{}, randomBytes(24)},
                           {"aes256-ctr", iv_bytes{}, randomBytes(32)},
                           {"aes128-gcm@openssh.com", randomBytes(12), randomBytes(16)},
                           {"aes256-gcm@openssh.com", randomBytes(12), randomBytes(32)},
                           {"chacha20-poly1305@openssh.com", iv_bytes{}, randomBytes(64)},
                         }));

TEST(SSHCipherTest, DecryptPacket_Poly1305TagVerify) {
  auto key = randomBytes(64);
  // chacha20-poly1305 will error on cipher_crypt instead of writing garbage, since part of the
  // cipher_crypt routine for this algorithm is verifying the poly1305 tag
  SSHCipher reader("chacha20-poly1305@openssh.com", iv_bytes{}, key, CipherMode::Read, 4);
  SSHCipher writer("chacha20-poly1305@openssh.com", iv_bytes{}, key, CipherMode::Write, 4);

  auto seqnr = 1234;
  wire::KexInitMsg msg;
  wire::test::populateFields(msg);
  Envoy::Buffer::OwnedImpl plaintext;
  ASSERT_OK(wire::encodePacket(plaintext, msg, writer.blockSize(), writer.aadLen()).status());

  Envoy::Buffer::OwnedImpl ciphertext;
  ASSERT_OK(writer.encryptPacket(seqnr, ciphertext, plaintext));

  auto packetLen = *reader.packetLength(seqnr, ciphertext);

  Envoy::Buffer::OwnedImpl decrypted;
  auto ciphertextLen = ciphertext.length();
  auto r = reader.decryptPacket(seqnr - 1, decrypted, ciphertext, packetLen);
  EXPECT_EQ(absl::InvalidArgumentError("decrypt failed: message authentication code incorrect"), r);
  ASSERT_EQ(ciphertextLen, ciphertext.length()); // buffer not drained
  r = reader.decryptPacket(seqnr + 1, decrypted, ciphertext, packetLen);
  EXPECT_EQ(absl::InvalidArgumentError("decrypt failed: message authentication code incorrect"), r);
  ASSERT_EQ(ciphertextLen, ciphertext.length()); // buffer not drained
  r = reader.decryptPacket(seqnr, decrypted, ciphertext, packetLen);
  ASSERT_OK(r);
  ASSERT_EQ(0, ciphertext.length());
}

class SSHCipherPacketLengthErrorsTestSuite : public testing::TestWithParam<
                                               std::tuple<
                                                 std::tuple<std::string, bytes, bytes>, // cipher
                                                 bytes                                  // input
                                                 >> {};

TEST_P(SSHCipherPacketLengthErrorsTestSuite, PacketLength_DecodedLengthTooSmall) {
  auto [cipher, input] = GetParam();
  auto reader = std::make_from_tuple<SSHCipher>(std::tuple_cat(cipher, std::tuple{CipherMode::Read, 4}));
  Envoy::Buffer::OwnedImpl in;
  wire::write(in, input);
  ASSERT_EQ(absl::InvalidArgumentError(fmt::format("invalid decoded packet length: {} (seqnr 0)",
                                                   in.peekBEInt<uint32_t>())),
            reader.packetLength(0, in).status());
}

INSTANTIATE_TEST_SUITE_P(SSHCipherPacketLengthErrorsTest, SSHCipherPacketLengthErrorsTestSuite,
                         testing::Combine(
                           testing::ValuesIn(std::vector<std::tuple<std::string, bytes, bytes>>{
                             {"aes128-ctr", iv_bytes{}, randomBytes(16)},
                             {"aes192-ctr", iv_bytes{}, randomBytes(24)},
                             {"aes256-ctr", iv_bytes{}, randomBytes(32)},
                             {"aes128-gcm@openssh.com", randomBytes(12), randomBytes(16)},
                             {"aes256-gcm@openssh.com", randomBytes(12), randomBytes(32)},
                           }),
                           testing::ValuesIn(std::vector<bytes>{
                             {0x00, 0x00, 0x00, 0x00, 0}, // 4 bytes length + 1 byte message id
                             {0x00, 0x00, 0x00, 0x00, 1},
                             {0x00, 0x00, 0x00, 0x03, 1},
                             {0x00, 0x00, 0x00, 0x04, 1}, // MinPacketSize-1
                             {0x00, 0x04, 0x00, 0x01, 1}, // MaxPacketSize+1
                             {0xFF, 0xFF, 0xFF, 0xFF, 1},
                           })));

class SSHCipherPaddingLengthErrorsTestSuite : public SSHCipherTestSuite {};

TEST_P(SSHCipherPaddingLengthErrorsTestSuite, PacketLength_PaddingError) {
  auto reader = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{CipherMode::Read, 4}));
  Envoy::Buffer::OwnedImpl input;
  auto blockSize = reader.blockSize();
  input.writeBEInt<uint32_t>(blockSize + 1); // packet length
  input.writeByte(0);                        // message id
  EXPECT_EQ(absl::InvalidArgumentError(fmt::format(
              "padding error: decoded packet length ({}) is not a multiple of the cipher block size ({})",
              blockSize + 1,
              blockSize)),
            reader.packetLength(0, input).status());
}

TEST_P(SSHCipherPaddingLengthErrorsTestSuite, EncryptPacket_InputTooSmall) {
  // encryptPacket doesn't fail under normal usage, but we can deliberately pass it invalid input.
  // for example, some ciphers (not chacha20) will fail if the input is smaller than one block.
  auto writer = std::make_from_tuple<SSHCipher>(std::tuple_cat(GetParam(), std::tuple{CipherMode::Write, 4}));
  Buffer::OwnedImpl in;
  in.writeBEInt<uint32_t>(writer.blockSize() - 1);
  bytes b;
  b.resize(writer.blockSize() - 1 - 4);
  wire::write(in, b);
  Buffer::OwnedImpl out;
  EXPECT_EQ(absl::InvalidArgumentError("encrypt failed: invalid argument"), writer.encryptPacket(0, out, in));
}

INSTANTIATE_TEST_SUITE_P(SSHCipherPaddingLengthErrorsTest, SSHCipherPaddingLengthErrorsTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<std::string, bytes, bytes>>{
                           {"aes128-ctr", iv_bytes{}, randomBytes(16)},
                           {"aes192-ctr", iv_bytes{}, randomBytes(24)},
                           {"aes256-ctr", iv_bytes{}, randomBytes(32)},
                           {"aes128-gcm@openssh.com", randomBytes(12), randomBytes(16)},
                           {"aes256-gcm@openssh.com", randomBytes(12), randomBytes(32)},
                         }));

TEST(SSHCipherTest, Init_UnknownCipher) {
  EXPECT_THROW_WITH_MESSAGE(SSHCipher("invalid", {}, {}, {}, {}),
                            Envoy::EnvoyException,
                            "unknown cipher: invalid");
}

TEST(SSHCipherTest, Init_CipherInitFail_WrongIVLen) {
  EXPECT_THROW_WITH_MESSAGE(SSHCipher("aes128-gcm@openssh.com", bytes(11, 0), bytes(16, 0), CipherMode::Read, 4),
                            Envoy::EnvoyException,
                            "failed to initialize cipher: invalid argument");
}

TEST(SSHCipherTest, Init_CipherInitFail_WrongKeyLen) {
  EXPECT_THROW_WITH_MESSAGE(SSHCipher("aes128-gcm@openssh.com", bytes(12, 0), bytes(15, 0), CipherMode::Read, 4),
                            Envoy::EnvoyException,
                            "failed to initialize cipher: invalid argument");
}

class SSHMacTestSuite : public testing::TestWithParam<std::tuple<std::string, int, int, bytes>> {};

TEST_P(SSHMacTestSuite, Setup) {
  auto [mac_alg, mac_type, digest_alg, key] = GetParam();
  ASSERT_EQ(MACKeySizes.at(mac_alg), key.size()); // sanity check
  SSHMac mac(mac_alg, key);
  ASSERT_TRUE(mac.isETM());
  ASSERT_EQ(mac.sshmacForTest()->mac_len, mac.length());
  if (mac_type == 1) {
    ASSERT_EQ(ssh_digest_bytes(digest_alg), mac.length());
  } else if (mac_type == 3) {
    ASSERT_EQ(16, mac.length()); // umac-128
  } else {
    PANIC("invalid test case");
  }
}

TEST_P(SSHMacTestSuite, Compute) {
  auto [mac_alg, mac_type, digest_alg, key] = GetParam();
  SSHMac mac(mac_alg, key);

  Buffer::OwnedImpl out;
  auto in = randomBytes(100);
  auto seqnr = 1;

  mac.compute(seqnr, out, in);

  bytes expected;
  expected.resize(mac.sshmacForTest()->mac_len);
  ASSERT_LE(expected.size(), SSH_DIGEST_MAX_LENGTH); // sanity check
  ASSERT_EQ(expected.size(), mac.length());
  ASSERT_TRUE(mac_compute(mac.sshmacForTest(),
                          seqnr,
                          in.data(), in.size(),
                          expected.data(), expected.size()) == 0);
}

TEST_P(SSHMacTestSuite, Verify) {
  auto [mac_alg, mac_type, digest_alg, key] = GetParam();

  for (int i = 0; i < 1000; i++) {
    SSHMac mac(mac_alg, key);

    auto input = randomBytes(absl::Uniform(rng, 1, 256));

    Buffer::OwnedImpl out;
    mac.compute(i, out, input);
    auto macBytes = wire::flushTo<bytes>(out);

    ASSERT_OK(mac.verify(i, input, macBytes));

    // check with a mac of wrong length
    ASSERT_EQ(absl::InvalidArgumentError("invalid argument"),
              mac.verify(i, input, bytes_view(macBytes).first(macBytes.size() - 1)));
  }
}

TEST(SSHMacTest, InvalidMacAlgorithm) {
  EXPECT_THROW_WITH_MESSAGE(SSHMac("never-before-seen", {}),
                            Envoy::EnvoyException,
                            "unknown mac: never-before-seen");
}

// from mac.c:
// 1 = SSH_DIGEST
// 2 = SSH_UMAC
// 3 = SSH_UMAC128
INSTANTIATE_TEST_SUITE_P(SSHMacTest, SSHMacTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<std::string, int, int, bytes>>{
                           {"hmac-sha2-256-etm@openssh.com", 1, SSH_DIGEST_SHA256, randomBytes(32)},
                           {"hmac-sha2-512-etm@openssh.com", 1, SSH_DIGEST_SHA512, randomBytes(64)},
                           {"umac-128-etm@openssh.com", 3, -1, randomBytes(16)},
                         }));

class HashTestSuite : public testing::TestWithParam<std::tuple<int, std::string>> {};

TEST_P(HashTestSuite, Hash) {
  auto [alg, algName] = GetParam();
  for (int i = 0; i < 1000; i++) {
    auto input = randomBytes(absl::Uniform(rng, 0, 1024));

    bytes digest(ssh_digest_bytes(alg), 0);
    ASSERT_TRUE(ssh_digest_memory(alg, input.data(), input.size(), digest.data(), digest.size()) == 0);

    {
      Hash ours(alg);
      ours.write(input);
      ASSERT_EQ(digest, ours.sum());
    }

    {
      Hash ours(algName);
      ours.write(input);
      ASSERT_EQ(digest, ours.sum());
    }
  }
}

TEST_P(HashTestSuite, BlockSize) {
  auto [alg, algName] = GetParam();
  detail::ssh_digest_ctx_ptr digest_ctx = ssh_digest_start(alg);
  auto expected = ssh_digest_blocksize(digest_ctx.get());

  {
    Hash h(alg);
    auto actual = h.blockSize();
    EXPECT_EQ(expected, actual);
  }

  {
    Hash h(algName);
    auto actual = h.blockSize();
    EXPECT_EQ(expected, actual);
  }
}

TEST_P(HashTestSuite, WriteSingleBytes) {
  auto [alg, algName] = GetParam();
  auto input = randomBytes(absl::Uniform(rng, 0, 1024));

  {
    Hash h1(alg);
    h1.write(input);
    auto sum1 = h1.sum();

    Hash h2(alg);
    for (uint8_t byte : input) {
      h2.write(byte);
    }
    auto sum2 = h2.sum();
    EXPECT_EQ(sum1, sum2);
  }

  {
    Hash h1(algName);
    h1.write(input);
    auto sum1 = h1.sum();

    Hash h2(algName);
    for (uint8_t byte : input) {
      h2.write(byte);
    }
    auto sum2 = h2.sum();
    EXPECT_EQ(sum1, sum2);
  }
}

INSTANTIATE_TEST_SUITE_P(HashTest, HashTestSuite,
                         testing::ValuesIn(std::vector<std::tuple<int, std::string>>{
                           {SSH_DIGEST_SHA1, "SHA1"},
                           {SSH_DIGEST_SHA256, "SHA256"},
                           {SSH_DIGEST_SHA384, "SHA384"},
                           {SSH_DIGEST_SHA512, "SHA512"},
                         }));

TEST(HashTest, InvalidAlgorithmID) {
  EXPECT_THROW_WITH_MESSAGE(Hash(SSH_DIGEST_MAX),
                            Envoy::EnvoyException,
                            "invalid hash algorithm id: 5");
}

TEST(HashTest, InvalidAlgorithmName) {
  EXPECT_THROW_WITH_MESSAGE(Hash("never-before-seen"),
                            Envoy::EnvoyException,
                            "invalid hash algorithm: never-before-seen");
}

} // namespace openssh::test