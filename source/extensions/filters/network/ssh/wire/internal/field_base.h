#pragma once

#include <compare> // IWYU pragma: keep
#include <cstddef>

namespace wire::internal {

struct field_base {
  // NB: a requirement for empty base class optimization is that the type must not be the same type
  // or a base of the type of the first non-static member of the most derived type.
  // In other words, if field_base is a base of field<T>, then field<T>'s first non-static member
  // cannot itself be a struct whose first non-static member is a field<T>, since it would have a
  // base of field_base and therefore prevent field_base from being optimized out, resulting in
  // extra padding being added before the first field. This would be the case with sub_messages of
  // structs with a sub_message as the first member, or fields of structs of fields.
  //
  // To work around this restriction, we can simply make the first non-static member of the most
  // derived class something that isn't field_base, by giving field_base a non-static data member.
  // If that member has size 0 and has [[no_unique_address]], then field_base will also be empty.
  //
  // MsgImplDefaults uses a different workaround by being a template class parameterized by
  // arbitrary unique types such that messages and sub-messages would have different types for
  // their respective MsgImplDefaults base class subobjects, and therefore are not required to have
  // unique addresses. The trick used in field_base prevents use of structured binding packs, which
  // is not an issue for fields, but it is an issue for messages because structured binding packs
  // are used for automatic encoding/decoding of messages.
  struct empty {
    constexpr auto operator<=>(const empty&) const = default;
  } _[0];
  constexpr auto operator<=>(const field_base&) const = default;
};

namespace test {
struct field_base_test : field_base {
  field_base foo;
  int bar;
};

static_assert(sizeof(field_base_test{}) == sizeof(int));
} // namespace test

} // namespace wire::internal