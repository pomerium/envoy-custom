
#include "source/common/type_traits.h"
#include "source/common/visit.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace test {

class Msg1 {};
class Msg2 {};
class Msg3 {};

template <typename T>
constexpr decltype(auto) as_nonconst(T&& t) { // NOLINT
  using nonconst_t = copy_reference_t<T&&, std::decay_t<T>>;
  return const_cast<nonconst_t>(t);
}

template <typename Visitor, typename... Fns>
constexpr decltype(auto) visit_helper(Visitor&& visitor, Fns... fns) {
  auto overloads = make_overloads<basic_visitor, decltype(visitor)>(fns...);
  return std::visit(overloads, std::forward<Visitor>(visitor));
}

TEST(VisitTest, Visit) {
  enum Result {
    CalledVisitMsg1NonConst = 1,
    CalledVisitMsg1Const,
    CalledVisitMsg1RvalueRef,

    CalledVisitMsg2NonConst,
    CalledVisitMsg2Const,
    CalledVisitMsg2RvalueRef,

    CalledDefaultAutoRef,
    CalledDefaultConstAutoRef,
    CalledDefaultAutoUniversalRef,
    CalledDefaultAutoPlain,
  };

  auto msg1 = [](Msg1&) { return CalledVisitMsg1NonConst; };
  auto constMsg1 = [](const Msg1&) { return CalledVisitMsg1Const; };
  auto rvalueRefMsg1 = [](Msg1&&) { return CalledVisitMsg1RvalueRef; };

  auto msg2 = [](Msg2&) { return CalledVisitMsg2NonConst; };
  auto constMsg2 = [](const Msg2&) { return CalledVisitMsg2Const; };
  auto rvalueRefMsg2 = [](Msg2&&) { return CalledVisitMsg2RvalueRef; };

  auto msg3 = [](Msg3&) { return CalledVisitMsg2NonConst; };
  auto constMsg3 = [](const Msg3&) { return CalledVisitMsg2Const; };
  auto rvalueRefMsg3 = [](Msg3&&) { return CalledVisitMsg2RvalueRef; };

  auto autoRef = [](auto&) { return CalledDefaultAutoRef; };
  auto constAutoRef = [](const auto&) { return CalledDefaultConstAutoRef; };
  auto universalRef = [](auto&&) { return CalledDefaultAutoUniversalRef; };
  auto autoNoRef = [](auto) { return CalledDefaultAutoPlain; };

  // clang-format off
  constexpr std::variant<Msg3, Msg1, Msg2> oneof{Msg1{}};
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(oneof),            msg1, msg2, msg3)                        == CalledVisitMsg1NonConst);
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(oneof),            constMsg1, msg2, msg3)                   == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(oneof),            constMsg1, constAutoRef)                 == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(oneof),            constMsg1, constMsg2, constAutoRef)      == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(oneof,                         constMsg1, constMsg2, constMsg3)         == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(oneof,                         constMsg1, autoRef)                      == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(oneof,                         constMsg1, constAutoRef)                 == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(oneof,                         constMsg1, universalRef)                 == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(std::move(oneof)), constMsg1, constMsg2, constAutoRef)      == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(std::move(oneof)), rvalueRefMsg1, universalRef)             == CalledVisitMsg1RvalueRef);
  EXPECT_STATIC_ASSERT(visit_helper(as_nonconst(std::move(oneof)), rvalueRefMsg1, rvalueRefMsg2, constMsg2,
                                                                   rvalueRefMsg3, constAutoRef)             == CalledVisitMsg1RvalueRef);
  // clang-format on

  // These are the same as above for reference, to see what visit_helper is doing - the type of the
  // object being visited (oneof) is passed to make_overloads explicitly, for validation purposes.
  // Its type cannot be deduced since the object being visited is only passed to std::visit, not to
  // make_overloads.
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(msg1, msg2, msg3), as_nonconst(oneof)) == CalledVisitMsg1NonConst);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(constMsg1, msg2, msg3), as_nonconst(oneof)) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(constMsg1, constAutoRef), as_nonconst(oneof)) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(constMsg1, constMsg2, constAutoRef), as_nonconst(oneof)) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype((oneof))>(constMsg1, constMsg2, constMsg3), oneof) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype((oneof))>(constMsg1, autoRef), oneof) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype((oneof))>(constMsg1, constAutoRef), oneof) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype((oneof))>(constMsg1, universalRef), oneof) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype(as_nonconst(std::move(oneof)))>(constMsg1, constMsg2, constAutoRef), as_nonconst(std::move(oneof))) == CalledVisitMsg1Const);
  EXPECT_STATIC_ASSERT(std::visit(make_overloads<basic_visitor, decltype(as_nonconst(std::move(oneof)))>(rvalueRefMsg1, rvalueRefMsg2, constMsg2, rvalueRefMsg3, constAutoRef), as_nonconst(std::move(oneof))) == CalledVisitMsg1RvalueRef);

  // no validation
  EXPECT_STATIC_ASSERT(std::visit(make_overloads_no_validation<basic_visitor>(constMsg1, universalRef), as_nonconst(oneof)) == CalledDefaultAutoUniversalRef);

  // the commented-out lines below would each trigger compile-time errors; corresponding validators follow

  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(constMsg1, autoRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(constMsg1), decltype(autoRef)>());
  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(constMsg1, constMsg2, autoRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(constMsg1), decltype(constMsg2), decltype(autoRef)>());
  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(constMsg1, constMsg2, universalRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(constMsg1), decltype(constMsg2), decltype(universalRef)>());

  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(rvalueRefMsg1, autoRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(rvalueRefMsg1), decltype(autoRef)>());
  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(rvalueRefMsg1, constAutoRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(rvalueRefMsg1), decltype(constAutoRef)>());
  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(rvalueRefMsg1, universalRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(rvalueRefMsg1), decltype(universalRef)>());
  // make_overloads<basic_visitor, decltype(as_nonconst(oneof))>(rvalueRefMsg1, autoNoRef);
  EXPECT_STATIC_ASSERT(!overload_validator<basic_visitor, decltype(as_nonconst(oneof))>::validate<decltype(rvalueRefMsg1), decltype(autoNoRef)>());

  // make_overloads<basic_visitor, decltype(oneof)>(msg1, universalRef);
  EXPECT_STATIC_ASSERT(!const_validator<true, decltype(msg1)>::validate());
}

} // namespace test