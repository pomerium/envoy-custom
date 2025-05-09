#pragma once

#include <optional>
#include <functional>

#include "envoy/common/optref.h"

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
