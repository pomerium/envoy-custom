#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/common/buffer/buffer_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

VersionExchanger::VersionExchanger(GenericProxy::ServerCodecCallbacks* callbacks,
                                   VersionExchangeCallbacks& handshakeCallbacks)
    : callbacks_(callbacks), version_exchange_callbacks_(handshakeCallbacks) {}

error VersionExchanger::doVersionExchange(Envoy::Buffer::Instance& buffer) noexcept {
  static const std::string server_version = "SSH-2.0-Envoy";

  auto err = readVersion(buffer);
  if (err) {
    return fmt::format("version exchange failed: {}", err.value());
  }

  Envoy::Buffer::OwnedImpl w;
  w.add(server_version);
  w.add("\r\n");
  callbacks_->writeToConnection(w);
  version_exchange_callbacks_.setVersionStrings(server_version, their_version_);
  return {};
}

error VersionExchanger::readVersion(Envoy::Buffer::Instance& buffer) {
  static const size_t max_version_string_bytes = 255;
  bool ok{};
  while (buffer.length() > 0 && their_version_.length() < max_version_string_bytes) {
    auto b = buffer.drainInt<uint8_t>();
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
    return "overflow reading version string";
  }

  if (their_version_.length() > 0 && their_version_[their_version_.length() - 1] == '\r') {
    their_version_.pop_back();
  }

  if (!their_version_.starts_with("SSH-")) {
    their_version_.clear();
    return "invalid version string";
  }

  return {};
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec