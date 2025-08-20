#pragma once

#include "source/common/common/fmt.h" // IWYU pragma: keep
#include "fmt/format.h"
#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage end

// Wraps an absl::Status with additional message context, but keeps the status code. Similar to
// fmt.Errorf.
inline absl::Status statusf(std::format_string<std::string_view> str, absl::Status underlying) {
  std::string_view msg = underlying.message();
  return absl::Status(static_cast<absl::StatusCode>(underlying.raw_code()),
                      fmt::vformat(str.get(), fmt::make_format_args(msg)));
}

// Returns a pair of strings: the first is the default abseil status code string, and the second is
// a more friendly 'Title Case' representation with the same string length, used in error messages.
constexpr inline std::pair<std::string_view, std::string_view> status_code_strings(absl::StatusCode c) {
  switch (c) {
  case absl::StatusCode::kOk:
    return {"OK",
            "OK"};
  case absl::StatusCode::kCancelled:
    return {"CANCELLED",
            "Cancelled"}; // [sic] match length of absl status code
  case absl::StatusCode::kUnknown:
    return {"UNKNOWN",
            "Unknown"};
  case absl::StatusCode::kInvalidArgument:
    return {"INVALID_ARGUMENT",
            "Invalid Argument"};
  case absl::StatusCode::kDeadlineExceeded:
    return {"DEADLINE_EXCEEDED",
            "Deadline Exceeded"};
  case absl::StatusCode::kNotFound:
    return {"NOT_FOUND",
            "Not Found"};
  case absl::StatusCode::kAlreadyExists:
    return {"ALREADY_EXISTS",
            "Already Exists"};
  case absl::StatusCode::kPermissionDenied:
    return {"PERMISSION_DENIED",
            "Permission Denied"};
  case absl::StatusCode::kResourceExhausted:
    return {"RESOURCE_EXHAUSTED",
            "Resource Exhausted"};
  case absl::StatusCode::kFailedPrecondition:
    return {"FAILED_PRECONDITION",
            "Failed Precondition"};
  case absl::StatusCode::kAborted:
    return {"ABORTED",
            "Aborted"};
  case absl::StatusCode::kOutOfRange:
    return {"OUT_OF_RANGE",
            "Out Of Range"};
  case absl::StatusCode::kUnimplemented:
    return {"UNIMPLEMENTED",
            "Unimplemented"};
  case absl::StatusCode::kInternal:
    return {"INTERNAL",
            "Internal"};
  case absl::StatusCode::kUnavailable:
    return {"UNAVAILABLE",
            "Unavailable"};
  case absl::StatusCode::kDataLoss:
    return {"DATA_LOSS",
            "Data Loss"};
  case absl::StatusCode::kUnauthenticated:
    return {"UNAUTHENTICATED",
            "Unauthenticated"};
  default:
    return {"", ""};
  }
}

constexpr inline std::string_view status_code_to_string(absl::StatusCode c) {
  return status_code_strings(c).second;
}

// Like absl::Status::ToString(), but replaces the status code strings with the equivalent
// 'Title Case' format, and gracefully handles non-standard status codes and empty messages.
inline std::string statusToString(const absl::Status& stat) {
  auto str = stat.ToString();
  if (stat.ok()) {
    return str;
  }
  auto [abslName, newName] = status_code_strings(static_cast<absl::StatusCode>(stat.raw_code()));
  if (!abslName.empty()) {
    str.replace(0, abslName.size(), newName);
  } else {
    // replace the empty string with something more useful
    str.insert(0, fmt::format("Code({})", stat.raw_code()));
  }
  if (str.ends_with(": ") && stat.message().empty()) {
    // trim empty message
    str.resize(str.size() - 2);
  }
  return str;
}
