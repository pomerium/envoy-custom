#pragma once

#include <optional>
#include <functional>

#include "envoy/common/optref.h"

// opt_ref is used in places where Envoy::OptRef cannot be used due to missing constexpr qualifiers
// on its constructors/methods. It is functionally equivalent, but not as ergonomic, so only use it
// if necessary.
template <typename T>
using opt_ref = std::optional<std::reference_wrapper<T>>;

template <typename T>
struct remove_optref : std::type_identity<T> {};

template <typename T>
struct remove_optref<opt_ref<T>> : std::type_identity<T> {};

template <typename T>
struct remove_optref<Envoy::OptRef<T>> : std::type_identity<T> {};

template <typename T>
using remove_optref_t = remove_optref<T>::type;
