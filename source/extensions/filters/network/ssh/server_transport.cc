#include "source/extensions/filters/network/ssh/server_transport.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <unistd.h>

#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/session.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/common/buffer/buffer_impl.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerCodec::SshServerCodec(Api::Api& api) : api_(api) {
  dsc_.reset(new DownstreamCallbacks(this));
  auto userAuth = std::make_unique<UserAuthService>(this, api);
  auto connection = std::make_unique<ConnectionService>(this, api);
  services_[userAuth->name()] = std::move(userAuth);
  services_[connection->name()] = std::move(connection);
};

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
      continue;
    }
    if (connection_state_) {
      Envoy::Buffer::OwnedImpl dec;
      auto err =
          connection_state_->cipher->decryptPacket(*connection_state_->seq_read, dec, buffer);
      if (err.has_value()) {
        ENVOY_LOG(error, "ssh: decryptPacket: {}", err.value());
        callbacks_->onDecodingFailure(fmt::format("ssh: decryptPacket: {}", err.value()));
        return;
      }
      (*connection_state_->seq_read)++;
      {
        auto [msg, err] = readPacket<AnyMsg>(dec);
        if (err.has_value()) {
          ENVOY_LOG(error, "ssh: readPacket: {}", err.value());
          callbacks_->onDecodingFailure(fmt::format("ssh: readPacket: {}", err.value()));
          return;
        }
        if (auto err = handleTransportMsg(std::move(msg)); err.has_value()) {
          ENVOY_LOG(error, "ssh: {}", err.value());
          callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.value()));
        }
      }
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
    : kex_(new Kex(callbacks, kexCallbacks, fs)), callbacks_(callbacks) {
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
  return {initial_kex_done_, std::nullopt};
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
  auto newReadState = new connection_state_t;
  newReadState->direction_read = clientKeys;
  newReadState->direction_write = serverKeys;
  newReadState->cipher = NewPacketCipher(newReadState->direction_read,
                                         newReadState->direction_write, kex_result.get());
  newReadState->seq_read = std::make_shared<uint32_t>(0);
  newReadState->seq_write = std::make_shared<uint32_t>(0);
  connection_state_.reset(newReadState);
}

error SshServerCodec::handleTransportMsg(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::Disconnect:
    ENVOY_LOG(debug, "received SshMessageType::Disconnect");
    break;
  case SshMessageType::Ignore:
    ENVOY_LOG(debug, "received SshMessageType::Ignore");
    break;
  case SshMessageType::Unimplemented:
    ENVOY_LOG(debug, "received SshMessageType::Unimplemented");
    break;
  case SshMessageType::Debug:
    ENVOY_LOG(debug, "received SshMessageType::Debug");
    break;
  case SshMessageType::ServiceRequest: {
    auto req = msg.unwrap<ServiceRequestMsg>();
    if (services_.contains(req.service_name)) {
      ServiceAcceptMsg accept;
      accept.service_name = req.service_name;
      return downstream().sendMessage(accept);
    }
    ENVOY_LOG(debug, "received SshMessageType::ServiceRequest");
    break;
  }
  case SshMessageType::ServiceAccept:
    ENVOY_LOG(debug, "received SshMessageType::ServiceAccept");
    break;
  case SshMessageType::ExtInfo:
    ENVOY_LOG(debug, "received SshMessageType::ExtInfo");
    break;
  case SshMessageType::KexInit:
    ENVOY_LOG(debug, "received SshMessageType::NewKeys");
    break;
  case SshMessageType::NewKeys:
    ENVOY_LOG(debug, "received SshMessageType::NewKeys");
    break;
  default:
    for (const auto& [name, svc] : services_) {
      if (svc->acceptsMessage(msg.msg_type)) {
        return svc->handleMessage(std::move(msg));
      }
    }
    return {fmt::format("unimplemented message type {}", static_cast<uint8_t>(msg.msg_type))};
  }
  return std::nullopt;
}

DownstreamCallbacks& SshServerCodec::downstream() { return *dsc_; }
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec