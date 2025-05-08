#pragma once

#include <concepts>

// explicit_t can be used to prevent implicit conversions in non-constructor function args, by
// requiring that the type of the value passed by the caller is exactly the same as the requested
// type.
//
// This is primarily used in functions that accept size_t, but also a (possibly integral) template
// argument in another parameter, e.g.:
//  template <typename T>
//  void foo(T t, size_t size) { ... }
// or
//  template <typename... Ints>
//  void foo(size_t size, Ints... integers) { ... }
//
// Unsigned integer types <=64 bits can be implicitly converted to size_t, but size_t often has
// different semantic meaning than other int types. explicit_t<size_t> can be used to prevent
// mistakenly passing non-size_t values:
//  template <typename T>
//  void foo(T t, explicit_t<size_t> auto size) { ... }
//
//  template <typename... Ints>
//  void foo(explicit_t<size_t> auto size, Ints... integers) { ... }
//
template <typename T, typename U>
concept explicit_t = std::same_as<T, U>;

template <typename T>
concept explicit_size_t = explicit_t<size_t, T>;

// any_of can be used to constrain the type of T to one of a given set of types.
template <typename T, typename... U>
concept any_of = (std::same_as<T, std::decay_t<U>> || ...);
