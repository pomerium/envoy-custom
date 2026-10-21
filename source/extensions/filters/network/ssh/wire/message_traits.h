#pragma once

#include "source/extensions/filters/network/ssh/wire/common.h"

namespace wire::detail {

template <typename T>
using submsg_group_t = T::submsg_group;

template <typename T>
concept SubmsgGroupMember = requires(T) { typename submsg_group_t<T>; };

// sub-messages
template <SshMessageType MT>
struct SubMsgGroup {};

template <typename T>
struct is_submsggroup : std::false_type {};

template <SshMessageType MT>
struct is_submsggroup<SubMsgGroup<MT>> : std::true_type {};

template <typename T>
constexpr bool is_submsggroup_v = is_submsggroup<T>::value;

// top level messages
enum class TopLevelMessageGroup {};

} // namespace wire::detail