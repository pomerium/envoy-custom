#include "source/extensions/filters/network/ssh/client_transport.h"

#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/transport.h"

extern "C" {
#include "openssh/ssherr.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshClientCodec::SshClientCodec(Api::Api& api,
                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
    : TransportCallbacks(*this), api_(api), config_(std::move(config)) {
  this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));
  user_auth_svc_ = std::make_unique<UpstreamUserAuthService>(*this, api);
  user_auth_svc_->registerMessageHandlers(*this);
  connection_svc_ = std::make_unique<ConnectionService>(*this, api, false);
  connection_svc_->registerMessageHandlers(*this);

  services_[user_auth_svc_->name()] = user_auth_svc_.get();
  services_[connection_svc_->name()] = connection_svc_.get();
}

void SshClientCodec::registerMessageHandlers(MessageDispatcher<AnyMsg>& dispatcher) const {
  dispatcher.registerHandler(SshMessageType::ServiceAccept, this);
  dispatcher.registerHandler(SshMessageType::GlobalRequest, this);
  dispatcher.registerHandler(SshMessageType::RequestSuccess, this);
  dispatcher.registerHandler(SshMessageType::RequestFailure, this);
  dispatcher.registerHandler(SshMessageType::Ignore, this);
  dispatcher.registerHandler(SshMessageType::Debug, this);
  dispatcher.registerHandler(SshMessageType::Unimplemented, this);
  dispatcher.registerHandler(SshMessageType::Disconnect, this);
}

void SshClientCodec::setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) {
  callbacks_ = &callbacks;
  kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), false);
  kex_->registerMessageHandlers(*this);
  version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_);
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
    } else if (dec.length() == 0) {
      ENVOY_LOG(debug, "received incomplete packet; waiting for more data");
      return;
    }
    auto prev = (*connection_state_->seq_read)++;
    ENVOY_LOG(debug, "read seqnr inc: {} -> {}", prev, *connection_state_->seq_read);

    {
      auto msg = readPacket<AnyMsg>(dec);
      if (!msg.ok()) {
        ENVOY_LOG(error, "ssh: readPacket: {}", msg.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: readPacket: {}", msg.status().message()));
        return;
      }
      if (msg->msg_type() == SshMessageType::NewKeys) {
        ENVOY_LOG(debug, "resetting read sequence number");
        *connection_state_->seq_read = 0;
      }
      ENVOY_LOG(info, "received message: type {}", msg->msg_type());
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
    auto& reqHeader = dynamic_cast<const SSHRequestHeaderFrame&>(frame);
    downstream_state_ = reqHeader.authState();
    return version_exchanger_->writeVersion(downstream_state_->server_version);
  }
  case FrameKind::RequestCommon: {
    return sendMessageToConnection(dynamic_cast<const SSHRequestCommonFrame&>(frame).message());
  }
  default:
    throw EnvoyException("bug: unknown frame kind");
  }
  (void)ctx;
  return absl::OkStatus();
}

void SshClientCodec::setKexResult(std::shared_ptr<kex_result_t> kex_result) {
  kex_result_ = kex_result;

  connection_state_->cipher = NewPacketCipher(
      connection_state_->direction_read,
      connection_state_->direction_write,
      kex_result.get());

  if (!first_kex_done_) {
    first_kex_done_ = true;

    if (auto stat = user_auth_svc_->requestService(); !stat.ok()) {
      ENVOY_LOG(error, "error requesting user auth: {}", stat.message());
      callbacks_->onDecodingFailure(fmt::format("error requesting user auth: {}", stat.message()));
      return;
    }
  }
}

absl::Status SshClientCodec::handleMessage(AnyMsg&& msg) {
  switch (msg.msgtype) {
  case SshMessageType::ServiceAccept: {
    auto acceptMsg = msg.unwrap<ServiceAcceptMsg>();
    if (services_.contains(acceptMsg.service_name)) {
      return services_[acceptMsg.service_name]->handleMessage(std::move(msg));
    }
    ENVOY_LOG(error, "received ServiceAccept message for unknown service {}", msg.msgtype);
    return absl::InternalError(
        fmt::format("received ServiceAccept message for unknown service {}", msg.msgtype));
  }
  case SshMessageType::GlobalRequest: {
    auto globalReq = msg.unwrap<GlobalRequestMsg>();
    if (globalReq.request_name == "hostkeys-00@openssh.com") {
      ENVOY_LOG(debug, "received hostkeys-00@openssh.com");
      // ignore this for now
      return absl::OkStatus();
    }
    ENVOY_LOG(debug, "forwarding global request");
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     std::move(globalReq)));
    return absl::OkStatus();
  }
  case SshMessageType::RequestSuccess: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     msg.unwrap<GlobalRequestSuccessMsg>()));
    return absl::OkStatus();
  }
  case SshMessageType::RequestFailure: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     msg.unwrap<GlobalRequestFailureMsg>()));
    return absl::OkStatus();
  }
  case SshMessageType::Ignore: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     msg.unwrap<IgnoreMsg>()));
    return absl::OkStatus();
  }
  case SshMessageType::Debug: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     msg.unwrap<DebugMsg>()));
    return absl::OkStatus();
  }
  case SshMessageType::Unimplemented: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     msg.unwrap<UnimplementedMsg>()));
    return absl::OkStatus();
  }
  case SshMessageType::Disconnect: {
    forward(std::make_unique<SSHResponseCommonFrame>(downstream_state_->stream_id,
                                                     msg.unwrap<DisconnectMsg>()));
    return absl::OkStatus();
  }
  default:
    PANIC("unimplemented");
  }
}

const connection_state_t& SshClientCodec::getConnectionState() const {
  return *connection_state_;
}

void SshClientCodec::writeToConnection(Envoy::Buffer::Instance& buf) const {
  return callbacks_->writeToConnection(buf);
}

const kex_result_t& SshClientCodec::getKexResult() const {
  return *kex_result_;
}

absl::StatusOr<bytearray> SshClientCodec::signWithHostKey(Envoy::Buffer::Instance& in) const {
  auto hostKey = kex_result_->Algorithms.host_key;
  if (auto k = kex_->getHostKey(hostKey); k) {
    auto inData = static_cast<uint8_t*>(in.linearize(in.length()));
    uint8_t* sig;
    size_t sig_len;
    auto err = sshkey_sign(k->priv.get(), &sig, &sig_len, inData, in.length(), hostKey.c_str(),
                           nullptr, nullptr, 0);
    if (err != 0) {
      return absl::InternalError(std::string(ssh_err(err)));
    }
    bytearray out;
    out.resize(sig_len);
    memcpy(out.data(), sig, sig_len);
    return out;
  }
  return absl::InternalError("no such host key");
}

const AuthState& SshClientCodec::authState() const {
  return *downstream_state_;
};

void SshClientCodec::forward(std::unique_ptr<SSHStreamFrame> frame) {
  switch (frame->frameKind()) {
  case FrameKind::ResponseHeader: {
    auto framePtr =
        std::unique_ptr<ResponseHeaderFrame>(dynamic_cast<ResponseHeaderFrame*>(frame.release()));
    callbacks_->onDecodingSuccess(std::move(framePtr));
    break;
  }
  case FrameKind::ResponseCommon: {
    auto framePtr =
        std::unique_ptr<ResponseCommonFrame>(dynamic_cast<ResponseCommonFrame*>(frame.release()));
    callbacks_->onDecodingSuccess(std::move(framePtr));
    break;
  }
  default:
    PANIC("bug: wrong frame type passed to SshClientCodec::forward");
  }
}

const pomerium::extensions::ssh::CodecConfig& SshClientCodec::codecConfig() const {
  return *config_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec