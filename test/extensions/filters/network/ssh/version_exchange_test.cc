#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "gtest/gtest.h"
#include "test/mocks/buffer/mocks.h"
#include "test/test_common/test_common.h"
#include "absl/random/random.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

enum ExchangeOrder {
  WriteFirst,
  ReadFirst,
};

class ReadVersionNoErrorsTest : public testing::TestWithParam<std::tuple<std::tuple<bytes, bytes>,
                                                                         VersionExchangeMode,
                                                                         ExchangeOrder>> {
public:
  ReadVersionNoErrorsTest()
      : vex_(transport_, vex_callbacks_, std::get<1>(GetParam())) {}

  void SetUp() override {
    EXPECT_FALSE(vex_.versionRead());
    EXPECT_FALSE(vex_.versionWritten());
    if (std::get<2>(GetParam()) == WriteFirst) {
      doWrite();
      EXPECT_TRUE(vex_.versionWritten());
    }
  }

  void TearDown() override {
    if (std::get<2>(GetParam()) == ReadFirst) {
      EXPECT_TRUE(vex_.versionRead());
      EXPECT_FALSE(vex_.versionWritten());
      doWrite();
      EXPECT_TRUE(vex_.versionWritten());
    } else {
      EXPECT_TRUE(vex_.versionRead());
      EXPECT_TRUE(vex_.versionWritten());
    }
    Buffer::OwnedImpl tmp;
    ASSERT_EQ(absl::FailedPreconditionError("version already read"), vex_.readVersion(tmp).status());
  }

  void doWrite() {
    auto [params, mode, order] = GetParam();
    auto [expected, terminator] = params;
    expected.append_range(terminator);

    switch (mode) {
    case VersionExchangeMode::Server:
      EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
      if (order == WriteFirst) {
        ASSERT_OK(vex_.writeVersion("ignored").status());
        EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete("ignored\r\n"_bytes, expected, bytes{}));
      } else {
        EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete("ignored\r\n"_bytes, expected, bytes{}));
        ASSERT_OK(vex_.writeVersion("ignored").status());
      }
      break;
    case VersionExchangeMode::Client:
      EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
      if (order == WriteFirst) {
        ASSERT_OK(vex_.writeVersion("ignored").status());
        EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete(expected, "ignored\r\n"_bytes, bytes{}));
      } else {
        EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete(expected, "ignored\r\n"_bytes, bytes{}));
        ASSERT_OK(vex_.writeVersion("ignored").status());
      }
      break;
    case VersionExchangeMode::None:
      PANIC("invalid test");
    }
  }

  MockTransportCallbacks transport_;
  MockVersionExchangeCallbacks vex_callbacks_;
  VersionExchanger vex_;
};

TEST_P(ReadVersionNoErrorsTest, ReadVersion) {
  auto [expected, terminator] = std::get<0>(GetParam());
  expected.append_range(terminator);
  Buffer::OwnedImpl buf;
  wire::write(buf, expected);
  auto r = vex_.readVersion(buf);
  ASSERT_OK(r.status());
  EXPECT_EQ(expected.size(), *r);
}

TEST_P(ReadVersionNoErrorsTest, ReadVersion_RandomPartitions) {
  auto [params, mode, order] = GetParam();
  auto [expected, terminator] = params;
  expected.append_range(terminator);

  absl::BitGen rng;
  Buffer::OwnedImpl buffer;
  for (size_t i = 0; i < expected.size(); i++) {
    uint8_t b = expected[i];
    buffer.writeByte(b);
    // 10% chance to call readVersion with the partial accumulated bytes
    if (i == expected.size() - 1) {
      auto r = vex_.readVersion(buffer);
      ASSERT_OK(r.status());
      ASSERT_EQ(expected.size(), *r);
      ASSERT_EQ(0, buffer.length());
    } else {
      if (absl::Uniform(rng, 0, 100) < 10) {
        auto r = vex_.readVersion(buffer);
        ASSERT_OK(r.status());
        ASSERT_EQ(0, *r);
      }
    }
  }
}

TEST_P(ReadVersionNoErrorsTest, ReadVersion_SingleBytePartitions) {
  auto [params, mode, order] = GetParam();
  auto [expected, terminator] = params;
  expected.append_range(terminator);
  Buffer::OwnedImpl buffer;
  for (size_t i = 0; i < expected.size(); i++) {
    buffer.writeByte(expected[i]);
    if (i == expected.size() - 1) {
      auto r = vex_.readVersion(buffer);
      ASSERT_OK(r.status());
      ASSERT_EQ(expected.size(), *r);
      ASSERT_EQ(0, buffer.length());
    } else {
      auto r = vex_.readVersion(buffer);
      ASSERT_OK(r.status());
      ASSERT_EQ(0, *r);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(ReadVersionNoErrors, ReadVersionNoErrorsTest,
                         testing::Combine(
                           testing::Combine(
                             testing::ValuesIn({
                               "SSH-2.0-billsSSH_3.6.3q3"_bytes,
                               "SSH-2.0-test"_bytes,
                               "SSH-2.0-test comment"_bytes,
                               "SSH-2.0-test comment with spaces"_bytes,
                               "SSH-2.0-test comment-with-dash"_bytes,
                               "SSH-2.0-"
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_bytes, // "SSH-2.0-" (8) + "a"*245 + "\r\n" (2) = 255
                             }),
                             testing::ValuesIn({
                               "\r\n"_bytes,
                               "\n"_bytes,
                             })),
                           testing::ValuesIn({
                             VersionExchangeMode::Client,
                             VersionExchangeMode::Server,
                           }),
                           testing::ValuesIn({
                             ReadFirst,
                             WriteFirst,
                           })));

class ClientReadVersionErrorsTest : public testing::TestWithParam<std::tuple<bytes, absl::Status>> {
public:
  ClientReadVersionErrorsTest()
      : vex_(transport_, vex_callbacks_, VersionExchangeMode::Client) {}

  void SetUp() override {
    EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
    ASSERT_OK(vex_.writeVersion("ignored").status());
  }

  MockTransportCallbacks transport_;
  MockVersionExchangeCallbacks vex_callbacks_;
  VersionExchanger vex_;
};

TEST_P(ClientReadVersionErrorsTest, ReadVersion) {
  auto [input, status] = GetParam();
  Buffer::OwnedImpl buf;
  wire::write(buf, input);
  EXPECT_EQ(status, vex_.readVersion(buf).status());
}

TEST_P(ClientReadVersionErrorsTest, ReadVersion_RandomPartitions) {
  auto [input, status] = GetParam();

  absl::BitGen rng;
  Buffer::OwnedImpl buffer;
  for (size_t i = 0; i < input.size(); i++) {
    uint8_t b = input[i];
    buffer.writeByte(b);
    // 10% chance to call readVersion with the partial accumulated bytes
    if (i == input.size() - 1) {
      auto r = vex_.readVersion(buffer);
      ASSERT_EQ(status, r.status());
    } else {
      if (absl::Uniform(rng, 0, 100) < 10) {
        auto r = vex_.readVersion(buffer);
        if (r.ok()) {
          ASSERT_EQ(0, *r);
        } else {
          ASSERT_EQ(status, r.status());
          return;
        }
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(ClientReadVersionErrors, ClientReadVersionErrorsTest,
                         testing::ValuesIn(std::vector<std::tuple<bytes, absl::Status>>{
                           {"invalid banner\0line\r\nSSH-2.0-test"_bytes, absl::InvalidArgumentError("banner line contains invalid characters")},
                           {"invalid banner line\r \nSSH-2.0-test"_bytes, absl::InvalidArgumentError("banner line contains invalid characters")},
                           {"invalid banner line\r\r\nSSH-2.0-test"_bytes, absl::InvalidArgumentError("banner line contains invalid characters")},
                           {"SSH-2.0-\r\n"_bytes, absl::InvalidArgumentError("invalid version string")},
                           {"SSH-2.0- -comment\r\n"_bytes, absl::InvalidArgumentError("invalid version string")},
                           {"SSH-2.0--foo\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-foo-bar\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0--foo comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-foo-bar comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-\tfoo comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-\t comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-\tcomment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-\x{7F}foo comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-\x{7F} comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-\x{7F}comment\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.1-test\r\n"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
                           {"SSH-\r\n"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
                           {"SSH-2\r\n"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
                           {"SSH-2.\r\n"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
                           {"SSH-2.0\r\n"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
                           {"SSH-2.0-with_ũnicode\r\n"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
                           {"SSH-2.0-"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"_bytes, // "SSH-2.0-" (8) + "a"*246 + "\r\n" (2) = 256
                            absl::InvalidArgumentError("version string too long")},
                         }));

class ClientReadVersionWithBannerNoErrorsTest : public testing::TestWithParam<std::tuple<bytes, bytes, bytes>> {
public:
  ClientReadVersionWithBannerNoErrorsTest()
      : vex_(transport_, vex_callbacks_, VersionExchangeMode::Client) {}

  void SetUp() override {
    EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
    ASSERT_OK(vex_.writeVersion("ignored").status());
  }

  MockTransportCallbacks transport_;
  MockVersionExchangeCallbacks vex_callbacks_;
  VersionExchanger vex_;
};

TEST_P(ClientReadVersionWithBannerNoErrorsTest, ReadVersion) {
  auto [banner, version, terminator] = GetParam();
  banner.append_range(terminator);
  version.append_range(terminator);
  EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete(version, "ignored\r\n"_bytes, banner));
  Buffer::OwnedImpl buf;
  wire::write(buf, banner);
  wire::write(buf, version);
  auto len = buf.length();
  auto r = vex_.readVersion(buf);
  ASSERT_OK(r.status());
  EXPECT_EQ(len, *r);
}

TEST_P(ClientReadVersionWithBannerNoErrorsTest, ReadVersion_RandomPartitions) {
  auto [banner, version, terminator] = GetParam();
  banner.append_range(terminator);
  version.append_range(terminator);
  EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete(version, "ignored\r\n"_bytes, banner));

  bytes complete;
  complete.append_range(banner);
  complete.append_range(version);

  absl::BitGen rng;
  Buffer::OwnedImpl buffer;
  for (size_t i = 0; i < complete.size(); i++) {
    uint8_t b = complete[i];
    buffer.writeByte(b);
    // 10% chance to call readVersion with the partial accumulated bytes
    if (i == complete.size() - 1) {
      auto r = vex_.readVersion(buffer);
      ASSERT_OK(r.status());
      ASSERT_EQ(complete.size(), *r);
      ASSERT_EQ(0, buffer.length());
    } else {
      if (absl::Uniform(rng, 0, 100) < 10) {
        auto r = vex_.readVersion(buffer);
        ASSERT_OK(r.status());
        ASSERT_EQ(0, *r);
      }
    }
  }
}

TEST_P(ClientReadVersionWithBannerNoErrorsTest, ReadVersion_SingleBytePartitions) {
  auto [banner, version, terminator] = GetParam();
  banner.append_range(terminator);
  version.append_range(terminator);
  EXPECT_CALL(vex_callbacks_, onVersionExchangeComplete(version, "ignored\r\n"_bytes, banner));

  bytes complete;
  complete.append_range(banner);
  complete.append_range(version);

  Buffer::OwnedImpl buffer;
  for (size_t i = 0; i < complete.size(); i++) {
    buffer.writeByte(complete[i]);
    if (i == complete.size() - 1) {
      auto r = vex_.readVersion(buffer);
      ASSERT_OK(r.status());
      ASSERT_EQ(complete.size(), *r);
      ASSERT_EQ(0, buffer.length());
    } else {
      auto r = vex_.readVersion(buffer);
      ASSERT_OK(r.status());
      ASSERT_EQ(0, *r);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(ClientReadVersionWithBannerNoErrors, ClientReadVersionWithBannerNoErrorsTest,
                         testing::Combine(
                           testing::ValuesIn({
                             "banner"_bytes,
                             "banner line 1\r\nbanner line 2"_bytes,
                             "banner line 1\nbanner line 2"_bytes,
                             "\nbanner line 2\nbanner line 3\n"_bytes,
                             "\r\nbanner line 2\r\nbanner line 3\r\n"_bytes,
                             (std::views::repeat("\r\n"_bytes, 1022) | std::views::join | std::ranges::to<bytes>()),                       // 1023 empty lines + version line
                             (std::views::repeat("banner\r\n"_bytes, 1022) | std::views::join | std::ranges::to<bytes>()),                 // 1023 lines + version line
                             (std::views::repeat("a"_bytes, 8190 /* reserve 2 for \r\n */) | std::views::join | std::ranges::to<bytes>()), // one very long line
                             std::ranges::join_view(
                               std::vector{
                                 std::views::repeat("a"_bytes, 4094) | std::views::join | std::ranges::to<bytes>(),
                                 "\r\n"_bytes,
                                 std::views::repeat("b"_bytes, 4094) | std::views::join | std::ranges::to<bytes>(),
                               }) |
                               std::ranges::to<bytes>(), // two long lines
                           }),
                           testing::ValuesIn({
                             "SSH-2.0-test"_bytes,
                             "SSH-2.0-test comment"_bytes,
                             "SSH-2.0-test more comments"_bytes,
                           }),
                           testing::ValuesIn({
                             "\r\n"_bytes,
                             "\n"_bytes,
                           })));

class ClientReadVersionWithBannerErrorsTest : public testing::TestWithParam<std::tuple<std::tuple<bytes, absl::Status>, bytes, bytes>> {
public:
  ClientReadVersionWithBannerErrorsTest()
      : vex_(transport_, vex_callbacks_, VersionExchangeMode::Client) {}

  void SetUp() override {
    EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
    ASSERT_OK(vex_.writeVersion("ignored").status());
  }

  MockTransportCallbacks transport_;
  MockVersionExchangeCallbacks vex_callbacks_;
  VersionExchanger vex_;
};

TEST_P(ClientReadVersionWithBannerErrorsTest, ReadVersion) {
  auto [banner_status, version, terminator] = GetParam();
  auto [banner, status] = banner_status;
  Buffer::OwnedImpl buf;
  wire::write(buf, banner);
  wire::write(buf, terminator);
  wire::write(buf, version);
  wire::write(buf, terminator);
  auto r = vex_.readVersion(buf);
  ASSERT_EQ(status, r.status());
}

TEST_P(ClientReadVersionWithBannerErrorsTest, ReadVersion_RandomPartitions) {
  auto [banner_status, version, terminator] = GetParam();
  auto [banner, status] = banner_status;
  bytes complete;
  complete.append_range(banner);
  complete.append_range(terminator);
  complete.append_range(version);
  complete.append_range(terminator);

  absl::BitGen rng;
  Buffer::OwnedImpl buffer;
  for (size_t i = 0; i < complete.size(); i++) {
    uint8_t b = complete[i];
    buffer.writeByte(b);
    // 10% chance to call readVersion with the partial accumulated bytes
    if (i == complete.size() - 1) {
      auto r = vex_.readVersion(buffer);
      ASSERT_EQ(status, r.status());
    } else {
      if (absl::Uniform(rng, 0, 100) < 10) {
        auto r = vex_.readVersion(buffer);
        if (r.ok()) {
          ASSERT_EQ(0, *r);
        } else {
          ASSERT_EQ(status, r.status());
          return;
        }
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(ClientReadVersionWithBannerErrors, ClientReadVersionWithBannerErrorsTest,
                         testing::Combine(
                           testing::ValuesIn(std::vector<std::tuple<bytes, absl::Status>>{
                             {(std::views::repeat("\r\n"_bytes, 1024) | std::views::join | std::ranges::to<bytes>()), absl::InvalidArgumentError("too many banner lines received")},
                             {(std::views::repeat("a"_bytes, 8193) | std::views::join | std::ranges::to<bytes>()), absl::InvalidArgumentError("banner line too long")},
                             {(std::views::repeat("a"_bytes, 16385) | std::views::join | std::ranges::to<bytes>()), absl::InvalidArgumentError("no ssh identification string received")},
                             {"SSH-2.0-"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaa\r\n"_bytes, // 255 'a's
                              absl::InvalidArgumentError("version string too long")},
                           }),
                           testing::ValuesIn({
                             "SSH-2.0-test"_bytes,
                             "SSH-2.0-test comment"_bytes,
                             "SSH-2.0-test more comments"_bytes,
                           }),
                           testing::ValuesIn({
                             "\r\n"_bytes,
                             "\n"_bytes,
                           })));

TEST(VersionExchangerTest, ServerReadBannerTextError) {
  MockTransportCallbacks transport;
  MockVersionExchangeCallbacks vex_callbacks;
  VersionExchanger vex(transport, vex_callbacks, VersionExchangeMode::Server);
  Buffer::OwnedImpl buffer("banner text\r\nSSH-2.0-test\r\n");
  auto r = vex.readVersion(buffer);
  EXPECT_EQ(absl::InvalidArgumentError("invalid version string"), r.status());
}

TEST(VersionExchangerTest, WriteVersionTwice) {
  MockTransportCallbacks transport;
  EXPECT_CALL(transport, writeToConnection(BufferStringEqual("foo\r\n"s)));
  MockVersionExchangeCallbacks vex_callbacks;
  VersionExchanger vex(transport, vex_callbacks, VersionExchangeMode::Server);
  auto r = vex.writeVersion("foo");
  EXPECT_OK(r.status());
  r = vex.writeVersion("foo");
  EXPECT_EQ(absl::FailedPreconditionError("version already written"), r.status());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec