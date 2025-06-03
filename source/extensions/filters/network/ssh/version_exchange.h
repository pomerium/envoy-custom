#pragma once

#pragma clang unsafe_buffer_usage begin
#include "absl/status/statusor.h"
#include "envoy/buffer/buffer.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

enum class VersionExchangeMode {
  None = 0,
  Server = 1,
  Client = 2,
};

class VersionExchangeCallbacks {
public:
  virtual ~VersionExchangeCallbacks() = default;
  virtual void onVersionExchangeCompleted(const bytes& server_version,
                                          const bytes& client_version,
                                          const bytes& banner_text) PURE;
};

class VersionExchanger final : public Logger::Loggable<Logger::Id::filter> {
public:
  VersionExchanger(TransportCallbacks& transport_callbacks,
                   VersionExchangeCallbacks& version_exchange_callbacks,
                   VersionExchangeMode mode);

  bool versionWritten() { return did_write_version_; }
  bool versionRead() { return did_read_version_; }

  absl::StatusOr<size_t> writeVersion(std::string_view ours);
  absl::StatusOr<size_t> readVersion(Envoy::Buffer::Instance& buffer);

  absl::Status validateBanner(const bytes& banner) const;
  absl::Status validateVersion(const bytes& version) const;

protected:
  bytes their_version_;
  bytes our_version_;
  bytes banner_text_;
  TransportCallbacks& transport_;
  VersionExchangeCallbacks& version_exchange_callbacks_;

private:
  void invokeCallbacksIfDone();
  bool is_server_;
  bool did_write_version_{false};
  bool did_read_version_{false};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec