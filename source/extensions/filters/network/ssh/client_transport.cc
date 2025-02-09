#include "source/extensions/filters/network/ssh/client_transport.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshClientCodec::SshClientCodec(Api::Api& api) : TransportCallbacks(*this), api_(api) {
  auto userAuth = std::make_unique<UserAuthService>(*this, api);
  userAuth->registerMessageHandlers(*this);
  auto connection = std::make_unique<ConnectionService>(*this, api);
  connection->registerMessageHandlers(*this);

  services_[userAuth->name()] = std::move(userAuth);
  services_[connection->name()] = std::move(connection);
}

void SshClientCodec::setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) {
  callbacks_ = &callbacks;
  kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), false);
  version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_);

  registerHandler(SshMessageType::KexInit, kex_.get());
  registerHandler(SshMessageType::KexECDHReply, kex_.get());
  registerHandler(SshMessageType::NewKeys, kex_.get());

  auto defaultState = new connection_state_t{};
  defaultState->cipher = NewUnencrypted();
  defaultState->direction_read = serverKeys;
  defaultState->direction_write = clientKeys;
  defaultState->seq_read = std::make_shared<uint32_t>(0);
  defaultState->seq_write = std::make_shared<uint32_t>(0);
  connection_state_.reset(defaultState);
}

void SshClientCodec::decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) {
  while (buffer.length() > 0) {
    if (!version_exchange_done_) {
      auto stat = version_exchanger_->readVersion(buffer);
      if (!stat.ok()) {
        ENVOY_LOG(error, "ssh: {}", stat.message());
        callbacks_->onDecodingFailure(stat.message());
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

GenericProxy::EncodingResult SshClientCodec::encode(const GenericProxy::StreamFrame& frame,
                                                    GenericProxy::EncodingContext& ctx) {
  switch (dynamic_cast<const SSHStreamFrame&>(frame).frameKind()) {
  case FrameKind::RequestHeader: {
    const auto& reqHeader = dynamic_cast<const SSHRequestHeaderFrame&>(frame);
    return version_exchanger_->writeVersion(reqHeader.ourVersion());
  }
  default:
    throw EnvoyException("bug: unknown frame kind");
  }
  (void)ctx;
  return absl::OkStatus();
}

void SshClientCodec::setKexResult(std::shared_ptr<kex_result_t> kex_result) {
  auto newReadState = new connection_state_t;
  newReadState->direction_read = serverKeys;
  newReadState->direction_write = clientKeys;
  newReadState->cipher = NewPacketCipher(newReadState->direction_read,
                                         newReadState->direction_write, kex_result.get());
  newReadState->seq_read = std::make_shared<uint32_t>(0);
  newReadState->seq_write = std::make_shared<uint32_t>(0);
  connection_state_.reset(newReadState);
}

absl::Status SshClientCodec::handleMessage(AnyMsg&& msg) {
  ENVOY_LOG(debug, "received message {} (ignoring)", msg.msg_type);
  return absl::UnimplementedError("unimplemented");
}

const connection_state_t& SshClientCodec::getConnectionState() const { return *connection_state_; }

void SshClientCodec::initUpstream(std::string_view, std::string_view) {
  throw EnvoyException("bug: initUpstream called on ClientCodec");
}

void SshClientCodec::writeToConnection(Envoy::Buffer::Instance& buf) const {
  return callbacks_->writeToConnection(buf);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec