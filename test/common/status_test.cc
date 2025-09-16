#include "source/common/status.h"
#include "gtest/gtest.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_split.h"
#include "absl/strings/str_join.h"

namespace test {

static std::vector<absl::StatusCode> wellKnownCodes = {
  absl::StatusCode::kOk,
  absl::StatusCode::kCancelled,
  absl::StatusCode::kUnknown,
  absl::StatusCode::kInvalidArgument,
  absl::StatusCode::kDeadlineExceeded,
  absl::StatusCode::kNotFound,
  absl::StatusCode::kAlreadyExists,
  absl::StatusCode::kPermissionDenied,
  absl::StatusCode::kResourceExhausted,
  absl::StatusCode::kFailedPrecondition,
  absl::StatusCode::kAborted,
  absl::StatusCode::kOutOfRange,
  absl::StatusCode::kUnimplemented,
  absl::StatusCode::kInternal,
  absl::StatusCode::kUnavailable,
  absl::StatusCode::kDataLoss,
  absl::StatusCode::kUnauthenticated,
};
TEST(StatusTest, StatusCodeStrings) {
  auto codes = wellKnownCodes;
  codes.push_back(absl::StatusCode(0));
  codes.push_back(absl::StatusCode(12345));

  for (const auto& code : codes) {
    auto standardString = absl::StatusCodeToString(code);
    auto [standard, formatted] = status_code_strings(code);
    EXPECT_EQ(standardString, standard);
    EXPECT_EQ(formatted, status_code_to_string(code));

    if (standard == "OK") {
      EXPECT_EQ(standard, formatted);
      continue;
    }

    // 'FOO_BAR' -> 'Foo Bar'
    std::vector<std::string> words = absl::StrSplit(absl::StrReplaceAll(absl::AsciiStrToLower(standardString), {{"_", " "}}), ' ');
    for (auto& word : words) {
      word[0] = absl::ascii_toupper(word[0]);
    }
    EXPECT_EQ(absl::StrJoin(words, " "), formatted);
  }
}

TEST(StatusTest, StatusToString) {
  auto testCases = std::vector<std::pair<absl::Status, std::string>>{
    {absl::OkStatus(), "OK"},
    {absl::Status(absl::StatusCode(12345), "foo bar"), "Code(12345): foo bar"},
    {absl::Status(absl::StatusCode(12345), ""), "Code(12345)"},
    {absl::Status(absl::StatusCode(12345), "test: "), "Code(12345): test: "},
  };
  for (auto code : wellKnownCodes) {
    if (code == absl::StatusCode::kOk) {
      continue;
    }
    testCases.push_back({absl::Status(code, ""), std::string(status_code_to_string(code))});
    testCases.push_back({absl::Status(code, "test message"), fmt::format("{}: test message", status_code_to_string(code))});
  }
  for (const auto& [status, expected] : testCases) {
    EXPECT_EQ(expected, statusToString(status));
  }
}

TEST(StatusTest, Statusf) {
  auto stat = absl::InvalidArgumentError("error message");
  {
    auto stat2 = statusf("additional context: {}", stat);
    EXPECT_EQ(absl::InvalidArgumentError("additional context: error message"), stat2);
  }

  {
    auto stat2 = statusf("error handling {}: {}", "something", stat);
    EXPECT_EQ(absl::InvalidArgumentError("error handling something: error message"), stat2);
  }
  {
    auto stat2 = statusf("{}: {}", stat, "details");
    EXPECT_EQ(absl::InvalidArgumentError("error message: details"), stat2);
  }
  {
    auto stat2 = statusf("{}: {}", stat, 1);
    EXPECT_EQ(absl::InvalidArgumentError("error message: 1"), stat2);
  }
}

} // namespace test