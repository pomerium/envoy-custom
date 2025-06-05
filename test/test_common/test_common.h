#pragma once

#include "source/common/optref.h"
#include "source/common/type_traits.h"
#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h" // IWYU pragma: keep
#include "absl/status/statusor.h"             // IWYU pragma: keep
#include "absl/strings/str_split.h"

#if defined(NDEBUG) || defined(ENVOY_CONFIG_COVERAGE)
#include "test/test_common/logging.h"
#endif
#pragma clang unsafe_buffer_usage end

#include "gtest/gtest.h"
#include "gmock/gmock.h" // IWYU pragma: keep

using namespace std::literals;

#define EXPECT_SHORT_READ(expr) EXPECT_THROW_WITH_MESSAGE(expr, EnvoyException, "short read")
#define EXPECT_BUFFER_UNDERFLOW(expr) EXPECT_THROW_WITH_MESSAGE(expr, EnvoyException, "buffer underflow")

#undef EXPECT_THROW
#define EXPECT_THROW #warning "use EXPECT_THROW_WITH_MESSAGE instead of EXPECT_THROW"

#define EXPECT_OK(expr)                                                                                                               \
  do {                                                                                                                                \
    absl::Status expect_ok_status = (expr);                                                                                           \
    EXPECT_TRUE(expect_ok_status.ok()) << "status code: " << expect_ok_status.code() << "; message: " << expect_ok_status.ToString(); \
  } while (false)

#define ASSERT_OK(expr)                                                                                                               \
  do {                                                                                                                                \
    absl::Status assert_ok_status = (expr);                                                                                           \
    ASSERT_TRUE(assert_ok_status.ok()) << "status code: " << assert_ok_status.code() << "; message: " << assert_ok_status.ToString(); \
  } while (false)

// NOLINTBEGIN(readability-identifier-naming)
template <typename T>
class WhenResolvedAsMatcher {
public:
  explicit WhenResolvedAsMatcher(const testing::Matcher<T>& matcher)
      : matcher_(matcher) {}

  void DescribeTo(::std::ostream* os) const {
    *os << "when resolved as " << ::type_name<T>() << ",";
    matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(::std::ostream* os) const {
    *os << "when resolved as " << ::type_name<T>() << ",";
    matcher_.DescribeNegationTo(os);
  }

  template <typename Overloaded>
  bool MatchAndExplain(Overloaded ov, testing::MatchResultListener* listener) const {
    opt_ref<T> t = ov.template resolve<T>();
    if (!t.has_value()) {
      *listener << "which did not resolve";
      return false;
    }
    return MatchPrintAndExplain(t.value().get(), this->matcher_, listener);
  }

protected:
  const testing::Matcher<T> matcher_;
};

template <typename T>
inline testing::PolymorphicMatcher<WhenResolvedAsMatcher<T>>
WhenResolvedAs(const testing::Matcher<T>& inner_matcher) {
  return testing::MakePolymorphicMatcher(WhenResolvedAsMatcher<T>{inner_matcher});
}

#define MSG(msg_type, ...)                                                                                                               \
  [&] {                                                                                                                                  \
    using MsgType_ = msg_type;                                                                                                           \
    if constexpr (wire::detail::is_overloaded_message<std::decay_t<MsgType_>>) {                                                         \
      return VariantWith<wire::detail::overload_set_for_t<std::remove_const_t<MsgType_>>>(WhenResolvedAs<MsgType_>(AllOf(__VA_ARGS__))); \
    } else {                                                                                                                             \
      return VariantWith<MsgType_>(AllOf(__VA_ARGS__));                                                                                  \
    }                                                                                                                                    \
  }()
// NOLINTEND(readability-identifier-naming)

#define FIELD_EQ(name, ...) FIELD_EQ_IMPL_(name, (__VA_ARGS__))

#define FIELD_EQ_IMPL_(name, ...) \
  Field(#name, &MsgType_::name, Eq(__VA_ARGS__))

#define CONCATENATE_IMPL_(a, b) a##b
#define CONCATENATE(a, b) CONCATENATE_IMPL_(a, b)
#define IN_SEQUENCE ::testing::InSequence CONCATENATE(in_sequence_, __LINE__)

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

using testing::_; // NOLINT(bugprone-reserved-identifier)
using testing::A;
using testing::AllOf;
using testing::AllOfArray;
using testing::An;
using testing::AnyNumber;
using testing::AnyOf;
using testing::AnyOfArray;
using testing::Contains;
using testing::DoAll;
using testing::Eq;
using testing::Expectation;
using testing::Field;
using testing::HasSubstr;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::NiceMock;
using testing::NotNull;
using testing::Property;
using testing::Return;
using testing::SaveArg;
using testing::Types;
using testing::VariantWith;
using testing::WhenDynamicCastTo;

using Envoy::EnvoyException;
namespace Buffer = Envoy::Buffer;

inline bool isDebuggerAttached() {
  std::ifstream status{"/proc/self/status"};
  std::string line;
  while (std::getline(status, line)) {
    if (line.starts_with("TracerPid:\t")) {
      return line[11] != '0';
    }
  }
  return false;
}

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
