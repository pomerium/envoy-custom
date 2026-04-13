#pragma once

#include <string>
#include <unordered_map>

#include "source/common/types.h"

#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end
constexpr auto EXTENSION_METADATA_SIZE_MAX = 1024 * 1024;

struct ExtensionMetadata {
  std::string id;
  std::string license;
  std::unordered_map<std::string, std::string> unknown_keys;
};

struct ExtensionInfo {
  const std::string path;
  ExtensionMetadata metadata;
};

absl::StatusOr<ExtensionMetadata> readExtensionMetadata(bytes_view extension_data);
absl::Status validateExtensionMetadata(const ExtensionMetadata& md);
