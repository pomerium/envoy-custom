#pragma once

#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h" // IWYU pragma: keep
#include "absl/status/statusor.h"             // IWYU pragma: keep

#if defined(NDEBUG) || defined(ENVOY_CONFIG_COVERAGE)
#include "test/test_common/logging.h"
#endif
#pragma clang unsafe_buffer_usage end

#include "gtest/gtest.h"
#include "gmock/gmock.h" // IWYU pragma: keep

#define EXPECT_SHORT_READ(expr) EXPECT_THROW_WITH_MESSAGE(expr, EnvoyException, "short read")
#define EXPECT_BUFFER_UNDERFLOW(expr) EXPECT_THROW_WITH_MESSAGE(expr, EnvoyException, "buffer underflow")

#undef EXPECT_THROW
#define EXPECT_THROW #warning "use EXPECT_THROW_WITH_MESSAGE instead of EXPECT_THROW"

#define EXPECT_STATIC_ASSERT_IMPL_(expr) \
  if consteval {                         \
    static_assert((expr));               \
  } else {                               \
    EXPECT_TRUE((expr));                 \
  }

// Expands to static_assert at compile time, and EXPECT_TRUE at runtime. Useful for testing
// constexpr code with coverage.
#define EXPECT_STATIC_ASSERT(...) \
  EXPECT_STATIC_ASSERT_IMPL_((__VA_ARGS__))

namespace wire::test {

using testing::_;
using testing::Eq;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::Types;

using Envoy::EnvoyException;
namespace Buffer = Envoy::Buffer;

} // namespace wire::test

// =================================================================================================
// code below vendored from envoy test/test_common/utility.h, which pulls in too many dependencies
// to include directly
// =================================================================================================

// NOLINTBEGIN

/*
  Macro to use for validating that a statement throws the specified type of exception, and that
  the exception's what() method returns a string which is matched by the specified matcher.
  This allows for expectations such as:

  EXPECT_THAT_THROWS_MESSAGE(
      bad_function_call(),
      EnvoyException,
      AllOf(StartsWith("expected prefix"), HasSubstr("some substring")));
*/
#define EXPECT_THAT_THROWS_MESSAGE(statement, expected_exception, matcher) \
  try {                                                                    \
    statement;                                                             \
    ADD_FAILURE() << "Exception should take place. It did not.";           \
  } catch (expected_exception & e) {                                       \
    EXPECT_THAT(std::string(e.what()), matcher);                           \
  }

// Expect that the statement throws the specified type of exception with exactly the specified
// message.
#define EXPECT_THROW_WITH_MESSAGE(statement, expected_exception, message) \
  EXPECT_THAT_THROWS_MESSAGE(statement, expected_exception, ::testing::Eq(message))

// Expect that the statement throws the specified type of exception with a message containing a
// substring matching the specified regular expression (i.e. the regex doesn't have to match
// the entire message).
#define EXPECT_THROW_WITH_REGEX(statement, expected_exception, regex_str) \
  EXPECT_THAT_THROWS_MESSAGE(statement, expected_exception, ::testing::ContainsRegex(regex_str))

// Expect that the statement throws the specified type of exception with a message that does not
// contain any substring matching the specified regular expression.
#define EXPECT_THROW_WITHOUT_REGEX(statement, expected_exception, regex_str) \
  EXPECT_THAT_THROWS_MESSAGE(statement, expected_exception,                  \
                             ::testing::Not(::testing::ContainsRegex(regex_str)))

// Expect that the statement hits an ENVOY_BUG containing the specified message.
#if defined(NDEBUG) || defined(ENVOY_CONFIG_COVERAGE)
// ENVOY_BUGs in release mode or in a coverage test log error.
#define EXPECT_ENVOY_BUG(statement, message) EXPECT_LOG_CONTAINS("error", message, statement)
#else
// ENVOY_BUGs in (non-coverage) debug mode is fatal.
#define EXPECT_ENVOY_BUG(statement, message) \
  EXPECT_DEBUG_DEATH(statement, ::testing::HasSubstr(message))
#endif

// NOLINTEND
