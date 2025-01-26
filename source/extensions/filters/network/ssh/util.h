#pragma once

#include <memory>

#include <cstdio>
extern "C" {
#include "openssh/sshkey.h"
}

namespace libssh {

template <typename T> void delete_impl(T*);

struct Deleter {
  template <typename T> void operator()(T* ptr) { delete_impl(ptr); }
};

template <typename T> using UniquePtr = std::unique_ptr<T, Deleter>;

using SshKeyPtr = UniquePtr<struct sshkey>;

} // namespace libssh