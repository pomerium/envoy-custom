#include "source/extensions/filters/network/ssh/server_transport.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <unistd.h>

#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerCodec::SshServerCodec(Api::Api& api) : TransportCallbacks(*this), api_(api) {
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
  kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), true);
  handshaker_ = std::make_unique<VersionExchanger>(*this, *kex_);

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
      auto stat = handshaker_->readVersion(buffer);
      if (!stat.ok()) {
        ENVOY_LOG(error, "ssh: {}", stat.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", stat.message()));
        return;
      }
      auto n = handshaker_->writeVersion(server_version_);
      if (!n.ok()) {
        ENVOY_LOG(error, "ssh: {}", stat.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", stat.message()));
        return;
      }
      version_exchange_done_ = true;
      continue;
    }

    Envoy::Buffer::OwnedImpl dec;
    auto stat = connection_state_->cipher->decryptPacket(*connection_state_->seq_read, dec, buffer);
    if (!stat.ok()) {
      ENVOY_LOG(error, "ssh: decryptPacket: {}", stat.message());
      callbacks_->onDecodingFailure(fmt::format("ssh: decryptPacket: {}", stat.message()));
      return;
    }
    (*connection_state_->seq_read)++;
    {
      auto msg = readPacket<AnyMsg>(dec);
      if (!msg.ok()) {
        ENVOY_LOG(error, "ssh: readPacket: {}", msg.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: readPacket: {}", msg.status().message()));
        return;
      }
      ENVOY_LOG(info, "received message: type {}", msg->msg_type);
      if (auto err = dispatch(std::move(*msg)); !err.ok()) {
        ENVOY_LOG(error, "ssh: {}", err.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.message()));
        return;
      }
    }
  }
}

GenericProxy::EncodingResult SshServerCodec::encode(const GenericProxy::StreamFrame& frame,
                                                    GenericProxy::EncodingContext& /*ctx*/) {
  const auto& msg = dynamic_cast<const SSHResponseHeaderFrame&>(frame);
  return sendMessageToConnection(msg.message());
}

GenericProxy::ResponsePtr SshServerCodec::respond(absl::Status status, absl::string_view data,
                                                  const Request&) {
  if (!status.ok()) {
    // something went wrong, send a disconnect message
    DisconnectMsg dc;
    dc.reason_code = SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE; // todo
    dc.description = data;
    // downstream().sendMessage(dc);

    return std::make_unique<SSHResponseHeaderFrame>(
        StreamStatus(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, false), std::move(dc));
  }
  return nullptr; // todo
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

absl::Status SshServerCodec::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::ServiceRequest: {
    auto req = msg.unwrap<ServiceRequestMsg>();
    if (services_.contains(req.service_name)) {
      ServiceAcceptMsg accept;
      accept.service_name = req.service_name;
      return sendMessageToConnection(accept).status();
    }
    ENVOY_LOG(debug, "received SshMessageType::ServiceRequest");
    break;
  }
  default:
    break;
  }
  return absl::OkStatus();
}

void SshServerCodec::initUpstream(std::string_view username, std::string_view hostname) {
  auto frame = std::make_unique<SSHRequestHeaderFrame>(username, hostname, server_version_);
  callbacks_->onDecodingSuccess(std::move(frame));
}

const connection_state_t& SshServerCodec::getConnectionState() const { return *connection_state_; }

void SshServerCodec::writeToConnection(Envoy::Buffer::Instance& buf) const {
  return callbacks_->writeToConnection(buf);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec