#pragma once

#include <string>
#include <sys/types.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

std::string copyTestdataToWritableTmp(const std::string& path, mode_t mode);

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec