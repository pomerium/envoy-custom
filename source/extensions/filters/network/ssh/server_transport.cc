#include "source/extensions/filters/network/ssh/server_transport.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <sshkey.h>
#include <unistd.h>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "envoy/network/connection.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerCodec::SshServerCodec(Api::Api& api,
                               std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                               CreateGrpcClientFunc create_grpc_client,
                               std::shared_ptr<ThreadLocal::TypedSlot<SharedThreadLocalData>> slot_ptr)
    : TransportBase(api, std::move(config)),
      DownstreamTransportCallbacks(*this),
      tls_(slot_ptr) {
  auto grpcClient = create_grpc_client();
  THROW_IF_NOT_OK_REF(grpcClient.status());
  mgmt_client_ = std::make_unique<StreamManagementServiceClient>(*grpcClient);
  channel_client_ = std::make_unique<ChannelStreamServiceClient>(*grpcClient);
  this->registerMessageHandlers(*mgmt_client_);
};

void SshServerCodec::setCodecCallbacks(Callbacks& callbacks) {
  TransportBase::setCodecCallbacks(callbacks);
  initServices();
  mgmt_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus, std::string err) {
    wire::DisconnectMsg dc;
    dc.reason_code = SSH2_DISCONNECT_CONNECTION_LOST; // todo
    dc.description = err;
    auto _ = sendMessageToConnection(dc);
    callbacks_->connection()->close(Network::ConnectionCloseType::FlushWrite, err);
  });
  mgmt_client_->connect();
}

void SshServerCodec::initServices() {
  user_auth_service_ = std::make_unique<DownstreamUserAuthService>(*this, api_);
  user_auth_service_->registerMessageHandlers(*this);
  user_auth_service_->registerMessageHandlers(*mgmt_client_);
  connection_service_ = std::make_unique<DownstreamConnectionService>(*this, api_, tls_);
  connection_service_->registerMessageHandlers(*this);

  service_names_.insert(user_auth_service_->name());
  service_names_.insert(connection_service_->name());
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

absl::Status SshServerCodec::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceRequestMsg& msg) {
      if (service_names_.contains(msg.service_name)) {
        wire::ServiceAcceptMsg accept;
        accept.service_name = msg.service_name;
        return sendMessageToConnection(accept).status();
      } else {
        return absl::UnavailableError("service not available");
      }
      ENVOY_LOG(debug, "received SshMessageType::ServiceRequest");
      return absl::OkStatus();
    },
    [&](wire::GlobalRequestMsg& msg) {
      auto stat = msg.msg.visit(
        [&](wire::HostKeysProveRequestMsg& msg) {
          auto resp = handleHostKeysProve(msg);
          if (!resp.ok()) {
            return resp.status();
          }
          wire::GlobalRequestSuccessMsg reply;
          reply.msg = **resp;
          return sendMessageToConnection(reply).status();
        },
        [](wire::HostKeysMsg&) {
          ENVOY_LOG(debug, "received hostkeys-00@openssh.com");
          // ignore this for now
          return absl::OkStatus();
        },
        [&msg](auto&) {
          ENVOY_LOG(debug, "ignoring global request {}", msg.request_name);
          return absl::OkStatus();
        });
      if (!stat.ok()) {
        return stat;
      }
      forward(std::make_unique<SSHRequestCommonFrame>(auth_state_->stream_id, std::move(msg)));

      return absl::OkStatus();
    },
    [&](wire::GlobalRequestSuccessMsg& msg) {
      forward(std::make_unique<SSHRequestCommonFrame>(auth_state_->stream_id, std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::GlobalRequestFailureMsg& msg) {
      forward(std::make_unique<SSHRequestCommonFrame>(auth_state_->stream_id, std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::IgnoreMsg& msg) {
      forward(std::make_unique<SSHRequestCommonFrame>(auth_state_->stream_id, std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::DebugMsg& msg) {
      forward(std::make_unique<SSHRequestCommonFrame>(auth_state_->stream_id, std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::UnimplementedMsg& msg) {
      forward(std::make_unique<SSHRequestCommonFrame>(auth_state_->stream_id, std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::DisconnectMsg& msg) {
      ENVOY_LOG(info, "received disconnect: {}", msg.description);
      return absl::CancelledError("disconnected");
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

absl::Status SshServerCodec::handleMessage(Grpc::ResponsePtr<ServerMessage>&& msg) { // NOLINT
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

void SshServerCodec::initUpstream(AuthStateSharedPtr s) {
  s->server_version = server_version_;
  auth_state_ = s;
  switch (auth_state_->channel_mode) {
  case ChannelMode::Normal: {
    auto frame = std::make_unique<SSHRequestHeaderFrame>(auth_state_);
    callbacks_->onDecodingSuccess(std::move(frame));

    ClientMessage upstream_connect_msg{};
    upstream_connect_msg.mutable_event()->mutable_upstream_connected()->set_stream_id(auth_state_->stream_id);
    sendMgmtClientMessage(upstream_connect_msg);
    break;
  }
  case ChannelMode::Hijacked: {
    auth_state_->hijacked_stream = channel_client_->start(
      connection_service_.get(), makeOptRefFromPtr(auth_state_->metadata.get()));
    auto _ = sendMessageToConnection(wire::EmptyMsg<wire::SshMessageType::UserAuthSuccess>{});
    break;
  }
  case ChannelMode::Handoff: {
    auto frame = std::make_unique<SSHRequestHeaderFrame>(auth_state_);
    callbacks_->connection()->readDisable(true);
    callbacks_->onDecodingSuccess(std::move(frame));

    ClientMessage upstream_connect_msg{};
    upstream_connect_msg.mutable_event()->mutable_upstream_connected()->set_stream_id(auth_state_->stream_id);
    sendMgmtClientMessage(upstream_connect_msg);
    break;
  }
  case ChannelMode::Multiplex:
    connection_service_->beginStream(*auth_state_, callbacks_->connection()->dispatcher());
    break;
  }
}

absl::StatusOr<bytes> SshServerCodec::signWithHostKey(bytes_view<> in) const {
  auto hostKey = kex_result_->algorithms.host_key;
  if (auto k = kex_->getHostKey(hostKey); k) {
    return k->priv.sign(in);
  }
  return absl::InternalError("no such host key");
}

const AuthState& SshServerCodec::authState() const {
  return *auth_state_;
}

AuthState& SshServerCodec::authState() {
  return *auth_state_;
}

void SshServerCodec::forward(std::unique_ptr<SSHStreamFrame> frame) {
  if (authState().handoff_info.handoff_in_progress) [[unlikely]] {
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
    wire::write_opt<wire::LengthPrefixed>(tmp, kex_result_->session_id);
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

void SshServerCodec::sendMgmtClientMessage(const ClientMessage& msg) {
  mgmt_client_->stream().sendMessage(msg, false);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec