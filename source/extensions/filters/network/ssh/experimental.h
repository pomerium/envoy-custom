#pragma once

#include <memory>

#define SSH_INCLUDED_EXPERIMENTAL_ 1

#ifdef SSH_EXPERIMENTAL
#include "envoy/thread_local/thread_local.h"
#include "source/extensions/filters/network/ssh/shared.h"
#endif

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

#ifdef SSH_EXPERIMENTAL
using ThreadLocalDataSlot = ThreadLocal::TypedSlot<ThreadLocalData>;
#else
using ThreadLocalDataSlot = struct {};
#endif
using ThreadLocalDataSlotSharedPtr = std::shared_ptr<ThreadLocalDataSlot>;
using ThreadLocalDataSlotPtr = std::unique_ptr<ThreadLocalDataSlot>;

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec