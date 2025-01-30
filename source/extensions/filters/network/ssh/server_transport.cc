#include "source/extensions/filters/network/ssh/server_transport.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>

#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/common/buffer/buffer_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

void SshServerCodec::setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) {
  this->callbacks_ = &callbacks;
}

void SshServerCodec::decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) {
  while (buffer.length() > 0) {
    if (!handshake_done_) {
      if (!handshaker_) {
        handshaker_ = std::make_unique<Handshaker>(callbacks_, *this, api_.fileSystem());
      }
      auto [done, err] = handshaker_->decode(buffer);
      if (err) {
        ENVOY_LOG(error, "ssh: {}", err.value());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.value()));
        return;
      }
      if (done) {
        ENVOY_LOG(debug, "ssh: handshake successful");
      }
      handshake_done_ = done;
    }
  }
}

GenericProxy::EncodingResult SshServerCodec::encode(const GenericProxy::StreamFrame& frame,
                                                    GenericProxy::EncodingContext& ctx) {
  (void)frame;
  (void)ctx;
  return absl::OkStatus();
}
GenericProxy::ResponsePtr SshServerCodec::respond(absl::Status, absl::string_view,
                                                  const GenericProxy::Request&) {
  return nullptr;
}

Handshaker::Handshaker(GenericProxy::ServerCodecCallbacks* callbacks, KexCallbacks& kexCallbacks,
                       Filesystem::Instance& fs)
    : kex_(new Kex(callbacks, kexCallbacks, fs)), callbacks_(callbacks),
      kex_callbacks_(kexCallbacks) {
  kex_->loadHostKeys();
}

std::tuple<bool, error> Handshaker::decode(Envoy::Buffer::Instance& buffer) noexcept {
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
  if (initial_kex_done_ && !sent_newkeys_) {
    Envoy::Buffer::OwnedImpl buf;
    writePacket(buf, EmptyPacket<SshMessageType::NewKeys>{});
    callbacks_->writeToConnection(buf);
    sent_newkeys_ = true;
  }

  return {sent_newkeys_, std::nullopt};
}

error Handshaker::doVersionExchange(Envoy::Buffer::Instance& buffer) noexcept {
  static const std::string server_version = "SSH-2.0-Envoy";

  auto err = readVersion(buffer);
  if (err) {
    return fmt::format("version exchange failed: {}", err.value());
  }

  Envoy::Buffer::OwnedImpl w;
  w.add(server_version);
  w.add("\r\n");
  callbacks_->writeToConnection(w);
  kex_->setVersionStrings(server_version, their_version_);
  return {};
}

error Handshaker::readVersion(Envoy::Buffer::Instance& buffer) {
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

void SshServerCodec::setKexResult(std::shared_ptr<kex_result_t> kex_result) {
  auto readCipher = NewPacketCipher(serverKeys, kex_result->Algorithms.r, kex_result);
  auto writeCipher = NewPacketCipher(clientKeys, kex_result->Algorithms.w, kex_result);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec