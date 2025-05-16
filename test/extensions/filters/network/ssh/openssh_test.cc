#include "source/common/span.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "gtest/gtest.h"
#include "test/extensions/filters/network/ssh/test_data.h"
#include "test/mocks/api/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/file_system_for_test.h"

extern "C" {
#include "openssh/ssh2.h"
#include "openssh/authfile.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/sshbuf.h"
}

namespace openssh::test {

using namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec::test;

std::string copyTestdataToWritableTmp(const std::string& path, mode_t mode) {
  const std::string runfilePath = Envoy::TestEnvironment::runfilesPath(path, "openssh_portable");
  auto data = Envoy::TestEnvironment::readFileToStringForTest(runfilePath);
  auto outPath = Envoy::TestEnvironment::temporaryPath(path);
  auto outPathSplit = Envoy::Filesystem::fileSystemForTest().splitPathFromFilename(outPath);
  EXPECT_OK(outPathSplit.status());
  Envoy::TestEnvironment::createPath(std::string(outPathSplit->directory_));
  Envoy::TestEnvironment::writeStringToFileForTest(outPath, data, true);
  EXPECT_EQ(0, chmod(outPath.c_str(), mode));
  return outPath;
}

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

TEST_P(SSHKeyTestSuite, FromPrivateKeyFilePath) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    auto r = SSHKey::fromPrivateKeyFile(privKeyPath);
    ASSERT_OK(r.status());
  }
}

TEST_P(SSHKeyTestSuite, FromPrivateKeyFilePath_BadPermissions) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    for (auto mode : {0640, 0644, 0666}) {
      auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), mode);
      auto r = SSHKey::fromPrivateKeyFile(privKeyPath);
      ASSERT_EQ(absl::PermissionDeniedError("bad permissions"), r.status());
    }
  }
}

TEST_P(SSHKeyTestSuite, FromToPublicKeyBlob) {
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    copyTestdataToWritableTmp(fmt::format("regress/unittests/sshkey/testdata/{}.pub", keyName), 0644);
    auto privKeyPath = copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600);
    auto priv = *SSHKey::fromPrivateKeyFile(privKeyPath);
    auto our_blob = *priv->toPublicKeyBlob();

    const auto rsa1Pub = privKeyPath + ".pub";
    detail::sshkey_ptr openssh_pubkey;
    ASSERT_EQ(0, sshkey_load_public(rsa1Pub.c_str(), std::out_ptr(openssh_pubkey), nullptr));
    CBytesPtr blob_ptr{};
    size_t blob_len{};
    ASSERT_EQ(0, sshkey_to_blob(openssh_pubkey.get(), std::out_ptr(blob_ptr), &blob_len));
    ASSERT_EQ(to_bytes(unsafe_forge_span(blob_ptr.get(), blob_len)), our_blob);

    auto our_pubkey = *SSHKey::fromPublicKeyBlob(our_blob);
    ASSERT_EQ(1, sshkey_equal(our_pubkey->sshKeyForTest(), openssh_pubkey.get()));
  }
}

TEST_P(SSHKeyTestSuite, FromPublicKeyBlob_Invalid) {
  auto r = SSHKey::fromPublicKeyBlob(bytes{'i', 'n', 'v', 'a', 'l', 'i', 'd'});
  EXPECT_EQ(absl::InvalidArgumentError("invalid format"), r.status());
}

TEST_P(SSHKeyTestSuite, Generate) {
  auto r = SSHKey::generate(KEY_RSA, 2048);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_RSA, (*r)->keyType());

  r = SSHKey::generate(KEY_ECDSA, 521);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_ECDSA, (*r)->keyType());

  r = SSHKey::generate(KEY_ED25519, 256);
  EXPECT_OK(r.status());
  EXPECT_EQ(KEY_ED25519, (*r)->keyType());

  r = SSHKey::generate(KEY_RSA, 256);
  EXPECT_EQ(absl::InvalidArgumentError("Invalid key length"), r.status());
}

TEST_P(SSHKeyTestSuite, Compare) {
  auto key1 = generate();
  auto key2 = generate();
  EXPECT_EQ(*key1, *key1);
  EXPECT_EQ(*key2, *key2);
  EXPECT_NE(*key1, *key2);
  EXPECT_EQ(**key1->toPublicKey(), *key1);
  EXPECT_NE(**key2->toPublicKey(), *key1);
  EXPECT_EQ(**key1->toPublicKey(), **key1->toPublicKey());
  EXPECT_NE(**key2->toPublicKey(), **key1->toPublicKey());
}

TEST_P(SSHKeyTestSuite, SignVerify) {
  auto key1 = generate();
  auto key2 = generate();

  auto key1_pub = *key1->toPublicKey();
  auto key2_pub = *key2->toPublicKey();

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
  auto stat = key_->convertToSignedUserCertificate(1, {"principal1", "principal2"}, {"extension1", "extension2"}, absl::Hours(24), *signer_);
  ASSERT_OK(stat);
  EXPECT_EQ(keyType + 4, key_->keyType()); // for the algorithms we use here, this is fine.
                                           // the openssh type converter function isn't public
  const auto* key = key_->sshKeyForTest();
  EXPECT_TRUE(sshkey_is_cert(key));
  EXPECT_TRUE(sshkey_check_cert_sigtype(key, sigAlgs.c_str()) == 0);

  EXPECT_EQ("user", sshkey_cert_type(key));

  bytes payload = {'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z'};
  auto sig = key_->sign(payload);
  ASSERT_OK(sig.status());

  auto pubKey = *key_->toPublicKey();
  ASSERT_OK(pubKey->verify(*sig, payload));
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_DifferentSignerAlgorithm) {
  // openssh PROTOCOL.certkeys states:
  //  Note that it is possible for a RSA certificate key to be signed by a
  //  Ed25519 or ECDSA CA key and vice-versa.
  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24),
                                                   *generateWithDifferentAlgorithm());
  ASSERT_OK(stat);
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_SignerIsCert) {
  // openssh PROTOCOL.certkeys states:
  //  "Chained" certificates, where the signature key type is a certificate type itself are
  //  NOT supported.

  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24), *signer_);
  ASSERT_OK(stat);

  auto key2 = generate();
  auto stat2 = key2->convertToSignedUserCertificate(2, {}, {}, absl::Hours(24), *key_);
  ASSERT_EQ(absl::InvalidArgumentError("invalid certificate signing key"), stat2);
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_AlreadyCert) {
  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24), *signer_);
  ASSERT_OK(stat);
  stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24), *signer_);
  // the exact error we get from openssh depends on the key algorithm; it will be one of these two
  ASSERT_THAT(stat, AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                          Eq(absl::InternalError("error in libcrypto"))));
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_KeyIsPublicKey) {
  auto key = generate();
  auto pub = *key->toPublicKey();
  auto stat = pub->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24), *signer_);
  // this is fine, the cert just won't be able to sign etc.
  ASSERT_OK(stat);
  ASSERT_THAT(pub->sign(bytes{'f', 'o', 'o'}).status(), AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                                                              Eq(absl::InternalError("error in libcrypto"))));
  ASSERT_EQ(absl::InvalidArgumentError("unknown or unsupported key type"), pub->toPrivateKeyPem().status());
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_SignerIsPublicKey) {
  auto key = generate();
  auto pub = *key->toPublicKey();
  auto stat = key_->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24), *pub);
  ASSERT_THAT(stat, AnyOf(Eq(absl::InvalidArgumentError("invalid argument")),
                          Eq(absl::InternalError("error in libcrypto"))));
}

TEST_P(SSHKeyCertTestSuite, ConvertToSignedUserCertificate_TooManyPrincipals) {
  std::vector<std::string> principals(SSHKEY_CERT_MAX_PRINCIPALS + 1, "asdf");
  auto stat = key_->convertToSignedUserCertificate(1, principals, {}, absl::Hours(24), *signer_);
  ASSERT_EQ(absl::InvalidArgumentError("number of principals (257) is more than the maximum allowed (256)"), stat);
}

TEST_P(SSHKeyCertTestSuite, Compare) {
  auto stat = key_->convertToSignedUserCertificate(1, {"principal1", "principal2"}, {"extension1", "extension2"}, absl::Hours(24), *signer_);
  EXPECT_EQ(*key_, *key_);
  EXPECT_EQ(*key_, **key_->toPublicKey());
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
      ASSERT_OK((*r)->convertToSignedUserCertificate(1, {}, {}, absl::Hours(24), *signer_));
    }
    key_ = std::move(r).value();
  }

  SSHKeyPtr key_;
  SSHKeyPtr signer_; // non-null if key is a cert type
};

TEST_P(SSHKeyPropertiesTestSuite, Fingerprint) {
  const auto* raw_key = key_->sshKeyForTest();
  auto expected = sshkey_fingerprint(raw_key, SSH_DIGEST_SHA256, SSH_FP_DEFAULT);
  ASSERT_NE(nullptr, expected);
  auto r = key_->fingerprint(SSH_FP_DEFAULT);
  EXPECT_OK(r.status());
  EXPECT_EQ(std::string_view(expected), std::string_view(*r));
}

TEST_P(SSHKeyPropertiesTestSuite, Fingerprint_InvalidFormat) {
  const auto* raw_key = key_->sshKeyForTest();
  auto expected = sshkey_fingerprint(raw_key, SSH_DIGEST_SHA256, sshkey_fp_rep(100));
  ASSERT_EQ(nullptr, expected); // sanity check
  auto r = key_->fingerprint(sshkey_fp_rep(100));
  EXPECT_EQ(absl::InvalidArgumentError("sshkey_fingerprint failed"), r.status());
}

TEST_P(SSHKeyPropertiesTestSuite, KeyTypeName) {
  auto [keyType, bits] = GetParam();
  const std::string_view expected = sshkey_ssh_name(key_->sshKeyForTest());
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
  std::vector<std::string> filenames;
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1"}) {
    filenames.push_back(copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600));
  }
  auto r = loadHostKeys(filenames);
  ASSERT_OK(r.status());
  ASSERT_EQ(3, r->size());
}

TEST(OpensshTest, LoadHostKeys_DuplicateAlgorithm) {
  std::vector<std::string> filenames;
  for (auto keyName : {"rsa_1", "ecdsa_1", "ed25519_1", "rsa_2"}) {
    filenames.push_back(copyTestdataToWritableTmp(absl::StrCat("regress/unittests/sshkey/testdata/", keyName), 0600));
  }
  auto stat = loadHostKeys(filenames);
  ASSERT_EQ(absl::InvalidArgumentError("host keys must have unique algorithms"), stat.status());
}

} // namespace openssh::test