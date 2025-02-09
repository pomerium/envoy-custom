#pragma once

#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "source/extensions/filters/network/ssh/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class VersionExchangeCallbacks {
public:
  virtual ~VersionExchangeCallbacks() = default;
  virtual void setVersionStrings(const std::string& ours, const std::string& peer) PURE;
};

class VersionExchanger {
public:
  VersionExchanger(GenericProxy::ServerCodecCallbacks* callbacks,
                   VersionExchangeCallbacks& handshakeCallbacks);

  absl::Status doVersionExchange(Envoy::Buffer::Instance& buffer) noexcept;

  absl::Status readVersion(Envoy::Buffer::Instance& buffer);

private:
  std::string their_version_;
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  VersionExchangeCallbacks& version_exchange_callbacks_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec