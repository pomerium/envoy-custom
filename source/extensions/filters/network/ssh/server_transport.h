#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "messages.h"
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

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

template <typename T> using error_or = std::tuple<T, error>;

class Handshaker {
public:
  Handshaker(GenericProxy::ServerCodecCallbacks* callbacks, Random::RandomGenerator& rng,
             Filesystem::Instance& fs)
      : callbacks_(callbacks), rng_(rng), fs_(fs) {}
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
      auto [done, err] = doInitialKex(buffer);
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

  std::tuple<bool, error> doInitialKex(Envoy::Buffer::Instance& buffer) noexcept {
    auto [peerKexInit, err] = decodePacket<KexInitMessage>(buffer, false); // no mac initially
    if (err) {
      return {false, err};
    }
    KexInitMessage serverKexInit{};
    serverKexInit.kex_algorithms = preferredKexAlgos;
    serverKexInit.encryption_algorithms_client_to_server = preferredCiphers;
    serverKexInit.encryption_algorithms_server_to_client = preferredCiphers;
    serverKexInit.mac_algorithms_client_to_server = supportedMACs;
    serverKexInit.mac_algorithms_server_to_client = supportedMACs;
    serverKexInit.compression_algorithms_client_to_server = {"none"};
    serverKexInit.compression_algorithms_server_to_client = {"none"};
    memcpy(serverKexInit.cookie.data(), reinterpret_cast<char*>(rng_.random()), 8);
    memcpy(serverKexInit.cookie.data() + 8, reinterpret_cast<char*>(rng_.random()), 8);

    return {true, std::nullopt};
  }

  void loadHostKeys() {
    static constexpr auto ed25519Priv = "/etc/ssh/ssh_host_ed25519_key";
    static constexpr auto ed25519Pub = "/etc/ssh/ssh_host_ed25519_key.pub";

    if (fs_.fileExists(ed25519Priv) && fs_.fileExists(ed25519Pub)) {
      auto priv = fs_.fileReadToEnd(ed25519Priv);
      if (priv.ok()) {
        bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(priv->data(), priv->size()));
        bssl::UniquePtr<EVP_PKEY> pkey(
            PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
        if (pkey == nullptr) {
          throw EnvoyException("Failed to read private key.");
        }
        auto pub = fs_.fileReadToEnd(ed25519Pub);
        if (pub.ok()) {
          std::vector<std::string> segments =
              absl::StrSplit(pub.value(), absl::ByAsciiWhitespace{});
          if (segments.size() >= 2) {
            auto type = segments[0];
            auto encodedKey = segments[1];
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, encodedKey.data(),
                                        CURVE25519_PUBKEY_SIZE);
          }
        }
      }
    }
  }

private:
  bool version_exchange_done_{};
  bool initial_kex_done_{};
  std::string their_version_;
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  Random::RandomGenerator& rng_;
  Filesystem::Instance& fs_;
  std::vector<HostKeyPair> host_keys_;
};

struct HostKeyPair {
  bssl::UniquePtr<EVP_PKEY> priv;
  bssl::UniquePtr<EVP_PKEY> pub;
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