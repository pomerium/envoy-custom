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
#include "source/extensions/filters/network/ssh/version_exchange.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerCodec::SshServerCodec(Api::Api& api) : api_(api) {
  dsc_.reset(new DownstreamCallbacks(this));
  auto userAuth = std::make_unique<UserAuthService>(*this, api);
  userAuth->registerMessageHandlers(*this);
  auto connection = std::make_unique<ConnectionService>(*this, api);
  connection->registerMessageHandlers(*this);

  registerHandler(SshMessageType::ServiceRequest, this);
  services_[userAuth->name()] = std::move(userAuth);
  services_[connection->name()] = std::move(connection);
};

void SshServerCodec::setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) {
  this->callbacks_ = &callbacks;
  kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem());
  handshaker_ = std::make_unique<VersionExchanger>(callbacks_, *kex_);

  registerHandler(SshMessageType::KexInit, kex_.get());
  registerHandler(SshMessageType::KexECDHInit, kex_.get());
  registerHandler(SshMessageType::NewKeys, kex_.get());

  auto defaultState = new connection_state_t{};
  defaultState->cipher = NewUnencrypted();
  defaultState->direction_read = clientKeys;
  defaultState->direction_write = serverKeys;
  defaultState->seq_read = std::make_shared<uint32_t>(0);
  defaultState->seq_write = std::make_shared<uint32_t>(0);
  connection_state_.reset(defaultState);
}

void SshServerCodec::decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) {
  while (buffer.length() > 0) {
    if (!version_exchange_done_) {
      auto err = handshaker_->doVersionExchange(buffer);
      if (err) {
        ENVOY_LOG(error, "ssh: {}", err.value());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.value()));
        return;
      }
      version_exchange_done_ = true;
      continue;
    }

    Envoy::Buffer::OwnedImpl dec;
    auto err = connection_state_->cipher->decryptPacket(*connection_state_->seq_read, dec, buffer);
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
      if (auto err = dispatch(std::move(msg)); err.has_value()) {
        ENVOY_LOG(error, "ssh: {}", err.value());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.value()));
        return;
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

error SshServerCodec::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
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
  default:
    break;
  }
  return std::nullopt;
}

DownstreamCallbacks& SshServerCodec::downstream() { return *dsc_; }

error DownstreamCallbacks::sendMessage(const SshMsg& msg) {
  if (!impl_->connection_state_) {
    throw EnvoyException("bug: no connection state");
  }
  Envoy::Buffer::OwnedImpl dec;
  writePacket(dec, msg, impl_->connection_state_->cipher->blockSize(MODE_WRITE),
              impl_->connection_state_->cipher->aadSize(MODE_WRITE));
  Envoy::Buffer::OwnedImpl enc;
  if (auto err = impl_->connection_state_->cipher->encryptPacket(
          *impl_->connection_state_->seq_write, enc, dec);
      err.has_value()) {
    return err;
  }
  (*impl_->connection_state_->seq_write)++;

  impl_->callbacks_->writeToConnection(enc);
  return std::nullopt;
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec