#pragma once

#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h"
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class VersionExchangeCallbacks {
public:
  virtual ~VersionExchangeCallbacks() = default;
  virtual void setVersionStrings(const std::string& ours, const std::string& peer) PURE;
};

class TransportCallbacks;

class VersionExchanger {
public:
  VersionExchanger(TransportCallbacks& transport_callbacks,
                   VersionExchangeCallbacks& version_exchange_callbacks);

  bool versionWritten() { return did_write_version_; }
  bool versionRead() { return did_read_version_; }

  absl::StatusOr<size_t> writeVersion(std::string_view ours);
  absl::Status readVersion(Envoy::Buffer::Instance& buffer);

protected:
  std::string their_version_;
  std::string our_version_;
  TransportCallbacks& transport_;
  VersionExchangeCallbacks& version_exchange_callbacks_;

private:
  bool did_write_version_{false};
  bool did_read_version_{false};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec