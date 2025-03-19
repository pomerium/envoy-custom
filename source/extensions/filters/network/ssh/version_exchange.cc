#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

VersionExchanger::VersionExchanger(TransportCallbacks& transport_callbacks,
                                   VersionExchangeCallbacks& version_exchange_callbacks)
    : transport_(transport_callbacks), version_exchange_callbacks_(version_exchange_callbacks) {}

absl::Status VersionExchanger::readVersion(Envoy::Buffer::Instance& buffer) {
  if (did_read_version_) {
    return absl::FailedPreconditionError("version already written");
  }
  did_read_version_ = true;

  static const size_t max_version_string_bytes = 255;
  bool ok{};
  while (buffer.length() > 0 && their_version_.length() < max_version_string_bytes) {
    auto b = buffer.drainInt<char>();
    if (b == '\n') {
      if (!their_version_.starts_with("SSH-")) {
        their_version_.clear();
        continue;
      }
      ok = true;
      break;
    }
    their_version_ += b;
  }
  if (!ok) {
    return absl::InvalidArgumentError("overflow reading version string");
  }

  if (their_version_.length() > 0 && their_version_[their_version_.length() - 1] == '\r') {
    their_version_.pop_back();
  }

  if (!their_version_.starts_with("SSH-")) {
    their_version_.clear();
    return absl::InvalidArgumentError("invalid version string");
  }

  if (!our_version_.empty() && !their_version_.empty()) {
    version_exchange_callbacks_.setVersionStrings(our_version_, their_version_);
  }
  return absl::OkStatus();
}

absl::StatusOr<size_t> VersionExchanger::writeVersion(std::string_view ours) {
  if (did_write_version_) {
    return absl::FailedPreconditionError("version already written");
  }
  did_write_version_ = true;

  our_version_ = ours;
  Envoy::Buffer::OwnedImpl w;
  w.add(ours);
  w.add("\r\n");
  size_t n = w.length();
  transport_.writeToConnection(w);
  if (!our_version_.empty() && !their_version_.empty()) {
    version_exchange_callbacks_.setVersionStrings(our_version_, their_version_);
  }
  return n;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec