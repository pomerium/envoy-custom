#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/keys.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "validate/validate.h"
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>
#include "source/common/buffer/buffer_impl.h"
#include "openssl/rand.h"
#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "openssl/curve25519.h"
#include "envoy/filesystem/filesystem.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Handshaker {
public:
  Handshaker(GenericProxy::ServerCodecCallbacks* callbacks, Filesystem::Instance& fs)
      : kex_(new Kex(callbacks, fs)), callbacks_(callbacks) {
    kex_->loadHostKeys();
  }
  std::tuple<bool, error> decode(Envoy::Buffer::Instance& buffer) noexcept {
    if (!version_exchange_done_) {
      auto err = doVersionExchange(buffer);
      if (err) {
        return {false, err};
      }
      version_exchange_done_ = true;
      return {false, std::nullopt};
    }
    if (!initial_kex_done_) {
      auto [done, err] = kex_->doInitialKex(buffer);
      if (err) {
        return {false, err};
      }
      initial_kex_done_ = done;
    }
    return {initial_kex_done_, std::nullopt};
  }

  error doVersionExchange(Envoy::Buffer::Instance& buffer) noexcept {
    static const std::string server_version = "SSH-2.0-Envoy\r\n";

    auto err = read_version(buffer);
    if (err) {
      return fmt::format("version exchange failed: {}", err.value());
    }

    Envoy::Buffer::OwnedImpl w;
    w.add(server_version);
    callbacks_->writeToConnection(w);
    kex_->setVersionStrings(server_version, their_version_);
    return {};
  }

  error read_version(Envoy::Buffer::Instance& buffer) {
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

private:
  bool version_exchange_done_{};
  bool initial_kex_done_{};
  std::string their_version_;
  std::unique_ptr<Kex> kex_;
  GenericProxy::ServerCodecCallbacks* callbacks_{};
};

class SshServerCodec : public Logger::Loggable<Logger::Id::filter>, public ServerCodec {
public:
  SshServerCodec(Api::Api& api) : api_(api) { ENVOY_LOG(debug, "constructor"); };
  ~SshServerCodec() { ENVOY_LOG(debug, "destructor"); };
  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

private:
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  bool handshake_done_{};
  std::unique_ptr<Handshaker> handshaker_;
  Api::Api& api_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec