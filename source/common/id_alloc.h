#pragma once

#include <concepts>
#include <set>

#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h"
#include "source/common/common/assert.h"
#pragma clang unsafe_buffer_usage end

// A basic numeric ID allocator for unsigned integer types.
// To allocate a new identifier, call alloc(). When an identifier is no longer needed and should
// be reused, call release(T).
template <std::unsigned_integral T, T Limit = std::numeric_limits<T>::max()>
class IDAllocator {
public:
  IDAllocator(T start_id)
      : next_(start_id) {}

  absl::StatusOr<T> alloc() {
    if (freed_.empty()) {
      if (next_ == Limit) {
        return absl::ResourceExhaustedError("failed to allocate ID");
      }
      return next_++;
    }
    return freed_.extract(freed_.begin()).value();
  }

  void release(T id) {
    RELEASE_ASSERT(id < next_ && !freed_.contains(id), "ID was never allocated or was already released");
    freed_.insert(id);
  }

private:
  T next_{0};
  std::set<T, std::less<T>> freed_;
};
