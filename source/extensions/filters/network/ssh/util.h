#pragma once

#include <memory>
#include <vector>
#include <string>

#include "fmt/std.h" // IWYU pragma: keep

extern "C" {
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using bytearray = std::vector<uint8_t>;

// using error = std::optional<std::string>;
// template <typename T> using error_or = std::tuple<T, error>;
using NameList = std::vector<std::string>;

}; // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

namespace libssh {

template <typename T>
void delete_impl(T*);

struct Deleter {
  template <typename T>
  void operator()(T* ptr) {
    delete_impl(ptr);
  }
};

template <typename T>
using UniquePtr = std::unique_ptr<T, Deleter>;

using SshKeyPtr = UniquePtr<struct sshkey>;
using SshBufPtr = UniquePtr<struct sshbuf>;

} // namespace libssh