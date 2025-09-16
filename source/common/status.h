#pragma once

#include "source/common/common/fmt.h" // IWYU pragma: keep
#include "fmt/format.h"
#include "source/common/type_traits.h"
#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h" // IWYU pragma: keep
#pragma clang unsafe_buffer_usage end

namespace {
template <typename... Args>
struct format_string_from : std::type_identity<fmt::format_string<Args...>> {};

// converts 'std::tuple<A, B, C>' into 'fmt::format_string<A, B, C>'
template <typename... Args>
struct format_string_from<std::tuple<Args...>> : std::type_identity<fmt::format_string<Args...>> {};

template <typename... Args>
using format_string_from_t = format_string_from<Args...>::type;

// calls fmt::make_format_args with tuple of reference_wrappers as args, which are unwrapped
template <typename... Args, size_t... Is>
constexpr decltype(auto) format_args_from_tuple(std::tuple<std::reference_wrapper<Args>...>& args,
                                                std::index_sequence<Is...>) {
  return fmt::make_format_args(std::get<Is>(args).get()...);
}
} // namespace

// Wraps an absl::Status with additional message context, but keeps the status code.
// Semantically equivalent to fmt.Errorf (except using the '{}' placeholders), for example:
//  auto stat = absl::InvalidArgumentError("error message");
//  statusf("error reading {}: {}", "foo", stat) => absl::InvalidArgumentError("error reading foo: error message")
template <typename... Args>
  requires contains_type<absl::Status, Args...>
inline constexpr absl::Status statusf(
  format_string_from_t<typelist_replace_t<absl::Status, std::string_view, Args...>> str,
  const Args&... args) {
  // find the index of the status arg in the args list
  constexpr size_t index_of_status_arg = index_of_type<absl::Status, Args...>::value;
  // create a tuple of reference_wrappers for each arg
  const auto argsTuple = std::tuple{std::cref(args)...};
  // obtain the status arg and its message (as an lvalue)
  const auto statusArg = std::get<index_of_status_arg>(argsTuple);
  const std::string_view message{statusArg.get().message()};
  // create a new tuple of arguments, with the status arg replaced by the string message
  auto substitutedArgs = [&]<size_t... Is>(std::index_sequence<Is...>) {
    return std::tuple { [&]<size_t I>() {
      if constexpr (I == index_of_status_arg) {
        return std::cref(message); // swap in the message
      } else {
        return std::get<I>(argsTuple); // keep the other args unchanged
      }
    }.template operator()<Is>()... };
  }(std::index_sequence_for<Args...>{});

  // create the format args for building the new status message
  auto fmtArgs = format_args_from_tuple(substitutedArgs,
                                        std::make_index_sequence<std::tuple_size_v<decltype(substitutedArgs)>>{});
  // create the new status with the formatted message and the existing status code
  return absl::Status(static_cast<absl::StatusCode>(statusArg.get().raw_code()),
                      fmt::vformat(str, fmtArgs));
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
