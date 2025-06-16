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

class ReadVersionTest : public testing::TestWithParam<std::tuple<std::tuple<bytes, bytes, absl::Status>,
                                                                 bytes,
                                                                 VersionExchangeMode,
                                                                 ExchangeOrder,
                                                                 std::function<std::vector<bytes>(const bytes&)>>> {
public:
  ReadVersionTest()
      : vex_(transport_, vex_callbacks_, std::get<2>(GetParam())) {}

  void SetUp() override {
    ASSERT_FALSE(vex_.versionRead());
    ASSERT_FALSE(vex_.versionWritten());
    if (std::get<3>(GetParam()) == WriteFirst) {
      doWrite();
      if (!skipped_) {
        ASSERT_TRUE(vex_.versionWritten());
      }
    }
  }

  void TearDown() override {
    if (skipped_) {
      return;
    }
    auto order = std::get<3>(GetParam());
    auto status = std::get<2>(std::get<0>(GetParam()));

    if (order == ReadFirst) {
      if (status.ok()) {
        ASSERT_TRUE(vex_.versionRead());
      } else {
        ASSERT_FALSE(vex_.versionRead());
      }
      ASSERT_FALSE(vex_.versionWritten());
      doWrite();
      ASSERT_TRUE(vex_.versionWritten());
    } else {
      if (status.ok()) {
        ASSERT_TRUE(vex_.versionRead());
      } else {
        ASSERT_FALSE(vex_.versionRead());
      }
      ASSERT_TRUE(vex_.versionWritten());
    }
  }

  void doWrite() {
    const auto& parts = getParts();
    if (parts.empty()) {
      skipped_ = true;
      return;
    }

    const auto& [params, terminator, mode, order, split] = GetParam();
    const auto& [banner, version, status] = params;
    bytes versionWithoutTerm = version;
    replaceTerm(versionWithoutTerm, {});
    switch (mode) {
    case VersionExchangeMode::Server:
      EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
      if (order == WriteFirst) {
        ASSERT_EQ(9, vex_.writeVersion("ignored"));
        if (status.ok()) {
          EXPECT_CALL(vex_callbacks_, onVersionExchangeCompleted("ignored"_bytes, versionWithoutTerm, bytes{}));
        }
      } else {
        if (status.ok()) {
          EXPECT_CALL(vex_callbacks_, onVersionExchangeCompleted("ignored"_bytes, versionWithoutTerm, bytes{}));
        }
        ASSERT_EQ(9, vex_.writeVersion("ignored"));
      }
      break;
    case VersionExchangeMode::Client:
      EXPECT_CALL(transport_, writeToConnection(BufferStringEqual("ignored\r\n"s)));
      if (order == WriteFirst) {
        ASSERT_EQ(9, vex_.writeVersion("ignored"));
        if (status.ok()) {
          EXPECT_CALL(vex_callbacks_, onVersionExchangeCompleted(versionWithoutTerm, "ignored"_bytes, banner));
        }
      } else {
        if (status.ok()) {
          EXPECT_CALL(vex_callbacks_, onVersionExchangeCompleted(versionWithoutTerm, "ignored"_bytes, banner));
        }
        ASSERT_EQ(9, vex_.writeVersion("ignored"));
      }
      break;
    case VersionExchangeMode::None:
      PANIC("invalid test");
    }
  }

  void replaceTerm(bytes& in, const bytes& with) {
    // replace "{term}" in the byte array with the terminator param
    auto view = bytes_view(in);
    if (auto sub = std::ranges::search(view, "{term}"_bytes); !sub.empty()) {
      auto idx = std::distance(view.begin(), sub.begin());
      bytes replace = to_bytes(view.first(idx));
      replace.append_range(with);
      replace.append_range(view.subspan(idx + sub.size()));
      std::swap(in, replace);
    }
  }

  const std::vector<bytes>& getParts() {
    if (parts_.has_value()) {
      return *parts_;
    }
    const auto& [params, terminator, mode, _, split] = GetParam();
    const auto& [banner, version, expectedStatus] = params;
    bytes versionWithTerm = version;
    replaceTerm(versionWithTerm, terminator);
    Buffer::OwnedImpl buf;
    bytes combined;
    if (mode == VersionExchangeMode::Client) {
      combined.append_range(banner);
    }
    combined.append_range(versionWithTerm);

    parts_ = split(combined);
    return *parts_;
  }
  MockTransportCallbacks transport_;
  MockVersionExchangeCallbacks vex_callbacks_;
  VersionExchanger vex_;
  bool skipped_{};

private:
  std::optional<std::vector<bytes>> parts_;
};

testing::AssertionResult isStatusWithValue(absl::StatusOr<size_t> actual, absl::Status expected_stat, size_t expected_value, const std::vector<bytes>& parts) {
  if (actual.status() != expected_stat) {
    auto stream = testing::AssertionFailure() << "status: " << actual.status() << "; expected: " << expected_stat << "; parts: ";
    for (const auto& part : parts) {
      stream << " \"" << absl::CEscape(std::string(reinterpret_cast<const char*>(part.data()), part.size())) << "\"";
    }
    return stream;
  }
  if (actual.ok()) {
    if (*actual != expected_value) {
      auto stream = testing::AssertionFailure() << "value: " << *actual << "; expected: " << expected_value << "; parts:";
      for (const auto& part : parts) {
        stream << " \"" << absl::CEscape(std::string(reinterpret_cast<const char*>(part.data()), part.size())) << "\"";
      }
      return stream;
    }
  }
  return testing::AssertionSuccess();
}

TEST_P(ReadVersionTest, ReadVersion) {
  const auto& [params, terminator, mode, _, split] = GetParam();
  const auto& [banner, version, expectedStatus] = params;
  const auto& parts = getParts();
  if (parts.empty()) {
    skipped_ = true;
    return;
  }
  size_t combinedLen{};
  Buffer::OwnedImpl buf;
  for (size_t i = 0; i < parts.size(); i++) {
    combinedLen += wire::write(buf, parts[i]);
    auto r = vex_.readVersion(buf);
    if (i == parts.size() - 1) {
      if (expectedStatus.ok()) {
        ASSERT_TRUE(isStatusWithValue(r, absl::OkStatus(), combinedLen, parts));
        ASSERT_EQ(0, buf.length());
      } else {
        // if we expect an error, the final r.status() should be that error
        ASSERT_TRUE(isStatusWithValue(r, expectedStatus, 0, parts));
      }
    } else {
      if (expectedStatus.ok()) {
        ASSERT_TRUE(isStatusWithValue(r, absl::OkStatus(), 0, parts));
      } else {
        // if we expect an error, readVersion should either return that error, or return 0/ok
        if (r.ok()) {
          ASSERT_TRUE(isStatusWithValue(r, absl::OkStatus(), 0, parts));
        } else {
          ASSERT_TRUE(isStatusWithValue(r, expectedStatus, 0, parts));
        }
      }
    }
  }
}

template <typename T>
std::vector<T> cat(std::initializer_list<std::vector<T>> items) {
  std::vector<T> out;
  for (auto&& b : items) {
    out.insert(out.end(), std::make_move_iterator(b.begin()),
               std::make_move_iterator(b.end()));
  }
  return out;
}

template <typename T, typename U, typename V>
std::vector<V> cartesianProduct(const std::vector<T>& ts, const std::vector<U>& us,
                                std::function<V(const T&, const U&)> transform) {
  std::vector<V> out;
  for (const auto& t : ts) {
    for (const auto& u : us) {
      out.push_back(transform(std::move(t), std::move(u)));
    }
  }
  return out;
}

static const auto noBannerTestCases = std::vector<std::tuple<bytes, bytes, absl::Status>>{
  {bytes{}, "SSH-2.0-billsSSH_3.6.3q3{term}"_bytes, absl::OkStatus()},
  {bytes{}, "SSH-2.0-test{term}"_bytes, absl::OkStatus()},
  {bytes{}, "SSH-2.0-test comment{term}"_bytes, absl::OkStatus()},
  {bytes{}, "SSH-2.0-test comment with spaces{term}"_bytes, absl::OkStatus()},
  {bytes{}, "SSH-2.0-test comment-with-dash{term}"_bytes, absl::OkStatus()},
  {bytes{}, "SSH-2.0-"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50x
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{term}"_bytes, // "SSH-2.0-" (8) + "a"*245 + "\r\n" (2) = 255
   absl::OkStatus()},
  {bytes{}, "SSH-2.0-{term}"_bytes, absl::InvalidArgumentError("invalid version string")},
  {bytes{}, "SSH-2.0- -comment{term}"_bytes, absl::InvalidArgumentError("invalid version string")},
  {bytes{}, "SSH-2.0--foo{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-foo-bar{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0--foo comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-foo-bar comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-\tfoo comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-\t comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-\tcomment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-\x{7F}foo comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-\x{7F} comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-\x{7F}comment{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2.0-with_ũnicode{term}"_bytes, absl::InvalidArgumentError("version string contains invalid characters")},
  {bytes{}, "SSH-2{term}"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
  {bytes{}, "SSH-2.{term}"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
  {bytes{}, "SSH-2.0{term}"_bytes, absl::InvalidArgumentError("unsupported protocol version")},
  {bytes{}, "SSH-2.0-"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"_bytes, // "SSH-2.0-" (8) + "a"*246 + "\r\n" (2) = 256
   absl::InvalidArgumentError("version string too long")},
};

static const auto bannerTestCasesNoError = cartesianProduct(
  std::vector<bytes>{
    "banner"_bytes,                                                                                               // normal
    "banner line 1\r\nbanner line 2"_bytes,                                                                       // two banner lines
    "banner line 1\nbanner line 2"_bytes,                                                                         // two banner lines (\n only)
    "\nbanner line 2\nbanner line 3\n"_bytes,                                                                     // four banner lines
    "\r\nbanner line 2\r\nbanner line 3\r\n"_bytes,                                                               // four banner lines (\n only)
    (std::views::repeat("\r\n"_bytes, 1022) | std::views::join | std::ranges::to<bytes>()),                       // 1023 empty lines + version line
    (std::views::repeat("banner\r\n"_bytes, 1022) | std::views::join | std::ranges::to<bytes>()),                 // 1023 lines + version line
    (std::views::repeat("a"_bytes, 8190 /* reserve 2 for \r\n */) | std::views::join | std::ranges::to<bytes>()), // one very long line
    std::ranges::join_view(std::vector{
      std::views::repeat("a"_bytes, 4094) | std::views::join | std::ranges::to<bytes>(),
      "\r\n"_bytes,
      std::views::repeat("b"_bytes, 4094) | std::views::join | std::ranges::to<bytes>(),
    }) |
      std::ranges::to<bytes>(), // two long lines
  },
  std::vector<bytes>{
    "SSH-2.0-test{term}"_bytes,
    "SSH-2.0-test comment{term}"_bytes,
    "SSH-2.0-test more comments{term}"_bytes,
  },
  std::function{[](const bytes& banner, const bytes& version) {
    bytes bannerWithTerm = banner;
    bannerWithTerm.push_back('\r');
    bannerWithTerm.push_back('\n');
    return std::make_tuple(bannerWithTerm, version, absl::OkStatus());
  }});

static const auto bannerTestCasesError = cartesianProduct(
  std::vector<std::tuple<bytes, absl::Status>>{
    {"invalid banner\0line\r\n"_bytes, absl::InvalidArgumentError("banner line contains invalid characters")},
    {"invalid banner line\r \n"_bytes, absl::InvalidArgumentError("banner line contains invalid characters")},
    {"invalid banner line\r\r\n"_bytes, absl::InvalidArgumentError("banner line contains invalid characters")},
    {(std::views::repeat("\r\n"_bytes, 1024) | std::views::join | std::ranges::to<bytes>()), absl::InvalidArgumentError("too many banner lines received")},
    {cat({(std::views::repeat("a"_bytes, 8193) | std::views::join | std::ranges::to<bytes>()), "\r\n"_bytes}), absl::InvalidArgumentError("banner line too long")},
    {(std::views::repeat("a"_bytes, 16385) | std::views::join | std::ranges::to<bytes>()), absl::InvalidArgumentError("no ssh identification string received")},
  },
  std::vector<bytes>{
    "SSH-2.0-test{term}"_bytes,
    "SSH-2.0-test comment{term}"_bytes,
    "SSH-2.0-test more comments{term}"_bytes,
  },
  std::function{[](const std::tuple<bytes, absl::Status>& banner_and_status, const bytes& version) {
    const auto& [banner, status] = banner_and_status;
    return std::make_tuple(banner, version, status);
  }});

namespace partitions {
std::vector<bytes> single(const bytes& input) {
  return std::vector<bytes>{input};
}
std::vector<bytes> splitEachByte(const bytes& input) {
  std::vector<bytes> elems;
  for (auto byte : input) {
    elems.push_back(bytes{byte});
  }
  return elems;
}
std::vector<bytes> splitBeforeFinalLF(const bytes& input) {
  if (input.back() == '\n') {
    return std::vector<bytes>{to_bytes(bytes_view(input).first(input.size() - 1)),
                              to_bytes(bytes_view(input).last(1))};
  } else {
    return {}; // skip
  }
}
std::vector<bytes> splitBeforeFinalCRLF(const bytes& input) {
  if (input.size() >= 2 && input[input.size() - 2] == '\r' && input[input.size() - 1] == '\n') {
    return std::vector<bytes>{to_bytes(bytes_view(input).first(input.size() - 2)),
                              to_bytes(bytes_view(input).last(2))};
  } else {
    return {}; // skip
  }
}
std::vector<bytes> splitOnDashes(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-2.0-"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      out.push_back(to_bytes(view.first(start))); // optional banner
    }
    out.push_back(to_bytes(view.subspan(start, 3)));     // "SSH"
    out.push_back(to_bytes(view.subspan(start + 3, 1))); // "-"
    out.push_back(to_bytes(view.subspan(start + 4, 3))); // "2.0"
    out.push_back(to_bytes(view.subspan(start + 7, 1))); // "-"
    out.push_back(to_bytes(view.subspan(start + 8)));    // remainder
  }
  return out;
}
std::vector<bytes> splitOnProtoVersionBeforeDash(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-2.0"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      out.push_back(to_bytes(view.first(start))); // optional banner
    }
    out.push_back(to_bytes(view.subspan(start, 7)));  // "SSH-2.0"
    out.push_back(to_bytes(view.subspan(start + 7))); // remainder
  }
  return out;
}
std::vector<bytes> splitAfterSSHDash(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      out.push_back(to_bytes(view.first(start))); // optional banner
    }
    out.push_back(to_bytes(view.subspan(start, 4)));  // "SSH-"
    out.push_back(to_bytes(view.subspan(start + 4))); // remainder
  }
  return out;
}
std::vector<bytes> splitWithinSSHDash(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      out.push_back(to_bytes(view.first(start))); // optional banner
    }
    out.push_back(to_bytes(view.subspan(start, 1)));     // "S"
    out.push_back(to_bytes(view.subspan(start + 1, 2))); // "SH"
    out.push_back(to_bytes(view.subspan(start + 3)));    // "-" + remainder
  }
  return out;
}
std::vector<bytes> splitBannerOnly(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-2.0"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      auto banner = view.first(start);
      out.push_back(to_bytes(banner.first(banner.size() / 2)));
      out.push_back(to_bytes(banner.subspan(banner.size() / 2)));
    } else {
      return {}; // skip
    }
    out.push_back(to_bytes(view.subspan(start)));
  }
  return out;
}
std::vector<bytes> splitBannerAndVersion(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-2.0"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      auto banner = view.first(start);
      out.push_back(to_bytes(banner.first(banner.size() / 2)));
      out.push_back(to_bytes(banner.subspan(banner.size() / 2)));
    } else {
      return {}; // skip
    }
    auto version = view.subspan(start);
    out.push_back(to_bytes(version.first(version.size() / 2)));
    out.push_back(to_bytes(version.subspan(version.size() / 2)));
  }
  return out;
}
std::vector<bytes> splitEachByteBannerOnly(const bytes& input) {
  auto view = bytes_view(input);
  std::vector<bytes> out;
  if (auto sub = std::ranges::search(view, "SSH-2.0"_bytes); !sub.empty()) {
    auto start = std::distance(view.begin(), sub.begin());
    if (start > 0) {
      auto banner = view.first(start);
      for (auto b : banner) {
        out.push_back({b});
      }
    } else {
      return {}; // skip
    }
    out.push_back(to_bytes(view.subspan(start)));
  }
  return out;
}
std::vector<bytes> random(const bytes& input) {
  // random
  absl::BitGen rng;
  std::vector<bytes> out;
  bytes current;
  for (size_t i = 0; i < input.size(); i++) {
    uint8_t b = input[i];
    current.push_back(b);
    if (absl::Uniform(rng, 0, 100) <= 10) {
      out.push_back(std::move(current));
      current.clear();
    }
  }
  if (!current.empty()) {
    out.push_back(std::move(current));
  }
  return out;
}
} // namespace partitions

INSTANTIATE_TEST_SUITE_P(
  ReadVersionClient, ReadVersionTest,
  testing::Combine(
    testing::ValuesIn(
      cat({
        noBannerTestCases,
        bannerTestCasesNoError,
        bannerTestCasesError,
      })),
    testing::ValuesIn({
      "\r\n"_bytes,
      "\n"_bytes,
    }),
    testing::ValuesIn({
      VersionExchangeMode::Client,
      // VersionExchangeMode::Server,
    }),
    testing::ValuesIn({
      ReadFirst,
      WriteFirst,
    }),
    testing::ValuesIn(std::vector<std::function<std::vector<bytes>(const bytes&)>>{
      partitions::single,
      partitions::splitEachByte,
      partitions::splitBeforeFinalLF,
      partitions::splitBeforeFinalCRLF,
      partitions::splitOnDashes,
      partitions::splitOnProtoVersionBeforeDash,
      partitions::splitAfterSSHDash,
      partitions::splitWithinSSHDash,
      partitions::splitBannerOnly,
      partitions::splitBannerAndVersion,
      partitions::splitEachByteBannerOnly,
      partitions::random,
    })));

INSTANTIATE_TEST_SUITE_P(
  ReadVersionServer, ReadVersionTest,
  testing::Combine(
    testing::ValuesIn(noBannerTestCases),
    testing::ValuesIn({
      "\r\n"_bytes,
      "\n"_bytes,
    }),
    testing::ValuesIn({
      // VersionExchangeMode::Client,
      VersionExchangeMode::Server,
    }),
    testing::ValuesIn({
      ReadFirst,
      WriteFirst,
    }),
    testing::ValuesIn(std::vector<std::function<std::vector<bytes>(const bytes&)>>{
      partitions::single,
      partitions::splitEachByte,
      partitions::splitBeforeFinalLF,
      partitions::splitBeforeFinalCRLF,
      partitions::splitOnDashes,
      partitions::splitOnProtoVersionBeforeDash,
      partitions::splitAfterSSHDash,
      partitions::splitWithinSSHDash,
      partitions::random,
    })));

TEST(VersionExchangerTest, ServerReadBannerTextError) {
  MockTransportCallbacks transport;
  MockVersionExchangeCallbacks vex_callbacks;
  VersionExchanger vex(transport, vex_callbacks, VersionExchangeMode::Server);
  Buffer::OwnedImpl buffer("banner text\r\nSSH-2.0-test\r\n");
  auto r = vex.readVersion(buffer);
  EXPECT_EQ(absl::InvalidArgumentError("invalid version string"), r.status());
}

TEST(VersionExchangerTest, WriteVersionTwiceDeath) {
  MockTransportCallbacks transport;
  EXPECT_CALL(transport, writeToConnection(BufferStringEqual("foo\r\n"s)));
  MockVersionExchangeCallbacks vex_callbacks;
  VersionExchanger vex(transport, vex_callbacks, VersionExchangeMode::Server);
  ASSERT_EQ(5, vex.writeVersion("foo"));
  EXPECT_DEATH(vex.writeVersion("foo"), "version already written");
}

TEST(VersionExchangerTest, ReadVersionTwiceDeath) {
  MockTransportCallbacks transport;
  MockVersionExchangeCallbacks vex_callbacks;
  VersionExchanger vex(transport, vex_callbacks, VersionExchangeMode::Server);
  Buffer::OwnedImpl tmp("SSH-2.0-test\r\n");
  ASSERT_OK(vex.readVersion(tmp).status());
  EXPECT_DEATH(vex.readVersion(tmp).IgnoreError(), "version already read");
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec