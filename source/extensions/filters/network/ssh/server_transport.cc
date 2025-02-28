#include "source/extensions/filters/network/ssh/server_transport.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <sshkey.h>
#include <unistd.h>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/network/connection.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher_impl.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerCodec::SshServerCodec(Api::Api& api,
                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                               CreateGrpcClientFunc create_grpc_client,
                               AccessLog::AccessLogFileSharedPtr access_log)
    : DownstreamTransportCallbacks(*this), api_(api), config_(config), access_log_(access_log) {
  auto grpcClient = create_grpc_client();
  THROW_IF_NOT_OK(grpcClient.status());
  mgmt_client_ = std::make_unique<StreamManagementServiceClient>(*grpcClient);
  channel_client_ = std::make_unique<ChannelStreamServiceClient>(*grpcClient);
  this->registerMessageHandlers(*mgmt_client_);
  this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));

  user_auth_service_ = std::make_unique<DownstreamUserAuthService>(*this, api);
  user_auth_service_->registerMessageHandlers(*this);
  user_auth_service_->registerMessageHandlers(*mgmt_client_);
  connection_service_ = std::make_unique<DownstreamConnectionService>(*this, api, access_log_);
  connection_service_->registerMessageHandlers(*this);

  service_names_.insert(user_auth_service_->name());
  service_names_.insert(connection_service_->name());
};

void SshServerCodec::setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) {
  this->callbacks_ = &callbacks;
  kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), true);
  kex_->registerMessageHandlers(*this);
  handshaker_ = std::make_unique<VersionExchanger>(*this, *kex_);

  auto defaultState = new connection_state_t{};
  defaultState->cipher = NewUnencrypted();
  defaultState->direction_read = clientKeys;
  defaultState->direction_write = serverKeys;
  defaultState->seq_read = std::make_shared<uint32_t>(0);
  defaultState->seq_write = std::make_shared<uint32_t>(0);
  connection_state_.reset(defaultState);

  mgmt_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus, std::string err) {
    wire::DisconnectMsg dc;
    dc.reason_code = SSH2_DISCONNECT_CONNECTION_LOST; // todo
    dc.description = err;
    auto _ = sendMessageToConnection(dc);
    callbacks_->connection()->close(Network::ConnectionCloseType::FlushWrite, err);
  });
  mgmt_client_->connect();
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
    } else if (dec.length() == 0) {
      ENVOY_LOG(debug, "received incomplete packet; waiting for more data");
      return;
    }

    auto prev = (*connection_state_->seq_read)++;
    ENVOY_LOG(debug, "read seqnr inc: {} -> {}", prev, *connection_state_->seq_read);

    {
      wire::AnyMsg anyMsg;
      auto n = wire::decodePacket<wire::AnyMsg>(dec, anyMsg);

      if (!n.ok()) {
        ENVOY_LOG(error, "ssh: readPacket: {}", n.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: readPacket: {}", n.status().message()));
        return;
      }
      auto msg = anyMsg.unwrap();
      if (!msg.ok()) {
        ENVOY_LOG(error, "ssh: error decoding message: {}", msg.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: error decoding message: {}", msg.status().message()));
        return;
      }
      if ((*msg)->msg_type() == wire::SshMessageType::NewKeys) {
        ENVOY_LOG(debug, "resetting read sequence number");
        *connection_state_->seq_read = 0;
      }
      ENVOY_LOG(debug, "received message: size: {}, type: {}", *n, (*msg)->msg_type());
      if (auto err = dispatch(std::move(**msg)); !err.ok()) {
        ENVOY_LOG(error, "ssh: {}", err.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.message()));
        return;
      }
    }
  }
}

GenericProxy::EncodingResult SshServerCodec::encode(const GenericProxy::StreamFrame& frame,
                                                    GenericProxy::EncodingContext& /*ctx*/) {
  const auto& msg = dynamic_cast<const SSHStreamFrame&>(frame);
  switch (msg.frameKind()) {
  case FrameKind::ResponseHeader: {
    if (authState().handoff_info.handoff_in_progress) {
      authState().handoff_info.handoff_in_progress = false;
      callbacks_->connection()->readDisable(false);
    }
    const auto& respHdr = dynamic_cast<const SSHResponseHeaderFrame&>(frame);
    return sendMessageToConnection(respHdr.message());
  }
  case FrameKind::ResponseCommon: {
    const auto& respHdr = dynamic_cast<const SSHResponseCommonFrame&>(frame);
    return sendMessageToConnection(respHdr.message());
  }
  default:
    PANIC("unimplemented");
  }
}

GenericProxy::ResponsePtr SshServerCodec::respond(absl::Status status, absl::string_view data,
                                                  const Request& req) {
  if (!status.ok()) {
    // something went wrong, send a disconnect message
    wire::DisconnectMsg dc;
    dc.reason_code = SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE; // todo
    dc.description = std::string(data);
    // downstream().sendMessage(dc);

    return std::make_unique<SSHResponseHeaderFrame>(
        req.frameFlags().streamId(), StreamStatus(SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, false), std::move(dc));
  } else {
    // auto m = AnyMsg::fromString(data);
    // switch (m.msg_type()) {
    // case wire::SshMessageType::UserAuthFailure: {
    //   auto _ = sendMessageToConnection(m);
    //   return std::make_unique<SSHResponseHeaderFrame>(
    //       req.frameFlags().streamId(), StreamStatus(0, false), m.unwrap<UserAuthFailureMsg>());
    // }
    // default:
    //   break;
    // }
    PANIC("unimplemented");
  }
  return nullptr; // todo
}

void SshServerCodec::setKexResult(std::shared_ptr<kex_result_t> kex_result) {
  kex_result_ = kex_result;

  connection_state_->cipher = NewPacketCipher(connection_state_->direction_read,
                                              connection_state_->direction_write,
                                              kex_result.get());
}

absl::Status SshServerCodec::handleMessage(wire::SshMsg&& msg) {
  switch (msg.msg_type()) {
  case wire::SshMessageType::ServiceRequest: {
    const auto& req = dynamic_cast<const wire::ServiceRequestMsg&>(msg);
    if (service_names_.contains(req.service_name)) {
      wire::ServiceAcceptMsg accept;
      accept.service_name = req.service_name;
      return sendMessageToConnection(accept).status();
    } else {
      return absl::UnavailableError("service not available");
    }
    ENVOY_LOG(debug, "received SshMessageType::ServiceRequest");

    break;
  }
  case wire::SshMessageType::GlobalRequest: {
    const auto& globalReq = dynamic_cast<const wire::GlobalRequestMsg&>(msg);
    auto stat = globalReq.msg.visit(
        [&](const wire::HostKeysProveRequestMsg& msg) {
          auto resp = handleHostKeysProve(msg);
          if (!resp.ok()) {
            return resp.status();
          }
          wire::GlobalRequestSuccessMsg reply;
          reply.msg = **resp;
          return sendMessageToConnection(reply).status();
        },
        [](const wire::HostKeysMsg&) {
          ENVOY_LOG(debug, "received hostkeys-00@openssh.com");
          // ignore this for now
          return absl::OkStatus();
        },
        [&](auto) {
          ENVOY_LOG(debug, "ignoring global request {}", globalReq.request_name);
          return absl::OkStatus();
        });
    if (!stat.ok()) {
      return stat;
    }
    forward(std::make_unique<SSHRequestCommonFrame>(downstream_state_->stream_id,
                                                    dynamic_cast<wire::GlobalRequestMsg&&>(msg)));

    return absl::OkStatus();
  }
  case wire::SshMessageType::RequestSuccess: {
    forward(std::make_unique<SSHRequestCommonFrame>(downstream_state_->stream_id,
                                                    dynamic_cast<wire::GlobalRequestSuccessMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::RequestFailure: {
    forward(std::make_unique<SSHRequestCommonFrame>(downstream_state_->stream_id,
                                                    dynamic_cast<wire::GlobalRequestFailureMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Ignore: {
    forward(std::make_unique<SSHRequestCommonFrame>(downstream_state_->stream_id,
                                                    dynamic_cast<wire::IgnoreMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Debug: {
    forward(std::make_unique<SSHRequestCommonFrame>(downstream_state_->stream_id,
                                                    dynamic_cast<wire::DebugMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Unimplemented: {
    forward(std::make_unique<SSHRequestCommonFrame>(downstream_state_->stream_id,
                                                    dynamic_cast<wire::UnimplementedMsg&&>(msg)));
    return absl::OkStatus();
  }
  case wire::SshMessageType::Disconnect: {
    ENVOY_LOG(info, "received disconnect: {}", dynamic_cast<wire::DisconnectMsg&&>(msg).description);
    return absl::CancelledError("disconnected");
  }
  default:
    break;
  }
  return absl::OkStatus();
}
absl::Status SshServerCodec::handleMessage(Grpc::ResponsePtr<ServerMessage>&& msg) {
  switch (msg->message_case()) {
  case ServerMessage::kStreamControl:
    switch (msg->stream_control().action_case()) {
    case pomerium::extensions::ssh::StreamControl::kCloseStream: {
      callbacks_->connection()->close(Network::ConnectionCloseType::AbortReset,
                                      msg->stream_control().close_stream().reason());
      return absl::OkStatus();
    }
    default:
      PANIC("unknown action case");
    }
  default:
    PANIC("unknown message case");
  }
}

void SshServerCodec::initUpstream(AuthStateSharedPtr downstreamState) {
  downstreamState->server_version = server_version_;
  downstream_state_ = downstreamState;
  switch (downstreamState->channel_mode) {
  case ChannelMode::Normal: {
    auto frame = std::make_unique<SSHRequestHeaderFrame>(downstreamState);
    callbacks_->onDecodingSuccess(std::move(frame));
    break;
  }
  case ChannelMode::Hijacked: {
    downstream_state_->hijacked_stream = channel_client_->start(
        connection_service_.get(), makeOptRefFromPtr(downstreamState->metadata.get()));
    auto _ = sendMessageToConnection(wire::EmptyMsg<wire::SshMessageType::UserAuthSuccess>{});
    break;
  }
  case ChannelMode::Handoff: {
    auto frame = std::make_unique<SSHRequestHeaderFrame>(downstreamState);
    callbacks_->connection()->readDisable(true);
    callbacks_->onDecodingSuccess(std::move(frame));
    break;
  }
  }
}

const connection_state_t& SshServerCodec::getConnectionState() const {
  return *connection_state_;
}

void SshServerCodec::writeToConnection(Envoy::Buffer::Instance& buf) const {
  return callbacks_->writeToConnection(buf);
}
const kex_result_t& SshServerCodec::getKexResult() const {
  return *kex_result_;
}

absl::StatusOr<bytes> SshServerCodec::signWithHostKey(bytes_view<> in) const {
  auto hostKey = kex_result_->Algorithms.host_key;
  if (auto k = kex_->getHostKey(hostKey); k) {
    return k->priv.sign(in);
  }
  return absl::InternalError("no such host key");
}

const AuthState& SshServerCodec::authState() const {
  return *downstream_state_;
}

AuthState& SshServerCodec::authState() {
  return *downstream_state_;
}

void SshServerCodec::forward(std::unique_ptr<SSHStreamFrame> frame) {
  if (authState().handoff_info.handoff_in_progress) {
    PANIC("forward() called during handoff, this should not happen");
  }
  switch (frame->frameKind()) {
  case FrameKind::RequestHeader: {
    auto framePtr =
        std::unique_ptr<RequestHeaderFrame>(dynamic_cast<RequestHeaderFrame*>(frame.release()));
    callbacks_->onDecodingSuccess(std::move(framePtr));
    break;
  }
  case FrameKind::RequestCommon: {
    auto framePtr =
        std::unique_ptr<RequestCommonFrame>(dynamic_cast<RequestCommonFrame*>(frame.release()));
    callbacks_->onDecodingSuccess(std::move(framePtr));
    break;
  }
  default:
    PANIC("bug: wrong frame type passed to SshServerCodec::forward");
  }
}

absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
SshServerCodec::handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg) {
  std::vector<bytes> signatures;
  for (const auto& keyBlob : *msg.hostkeys) {
    auto key = openssh::SSHKey::fromBlob(keyBlob);
    if (!key.ok()) {
      return key.status();
    }
    auto hostKey = kex_->getHostKey(key->name());
    if (*key != hostKey->pub) {
      // not our key?
      ENVOY_LOG(error, "client requested to prove ownership of a key that isn't ours");
      return absl::InvalidArgumentError("requested key is invalid");
    }
    Envoy::Buffer::OwnedImpl tmp;
    wire::write_opt<wire::LengthPrefixed>(tmp, "hostkeys-prove-00@openssh.com"s);
    wire::write_opt<wire::LengthPrefixed>(tmp, kex_result_->SessionID);
    wire::write_opt<wire::LengthPrefixed>(tmp, keyBlob);
    auto sig = key->sign(wire::flushTo<bytes>(tmp));
    if (!sig.ok()) {
      return absl::InternalError(fmt::format("sshkey_sign failed: {}", sig.status()));
    }
    signatures.push_back(std::move(*sig));
  }
  auto resp = std::make_unique<wire::HostKeysProveResponseMsg>();
  resp->signatures = std::move(signatures);
  return resp;
}

const pomerium::extensions::ssh::CodecConfig& SshServerCodec::codecConfig() const {
  return *config_;
};

void SshServerCodec::sendMgmtClientMessage(const ClientMessage& msg) {
  mgmt_client_->stream().sendMessage(msg, false);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec