#include "source/extensions/filters/network/ssh/server_transport.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <sshkey.h>
#include <unistd.h>

#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerTransport::SshServerTransport(Api::Api& api,
                                       std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                       CreateGrpcClientFunc create_grpc_client,
                                       std::shared_ptr<ThreadLocal::TypedSlot<ThreadLocalData>> slot_ptr)
    : TransportBase(api, std::move(config)),
      DownstreamTransportCallbacks(*this),
      tls_(slot_ptr) {
  auto grpcClient = create_grpc_client();
  THROW_IF_NOT_OK_REF(grpcClient.status());
  mgmt_client_ = std::make_unique<StreamManagementServiceClient>(*grpcClient);
  channel_client_ = std::make_unique<ChannelStreamServiceClient>(*grpcClient);

  wire::ExtInfoMsg extInfo;
  wire::PingExtension pingExt;
  pingExt.version = "0";
  extInfo.extensions->emplace_back(std::move(pingExt));
  outgoing_ext_info_ = std::move(extInfo);
};

void SshServerTransport::registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) {
  // initial key exchange must be complete before handling any non-kex messages
  ASSERT(kex_result_ != nullptr);

  dispatcher.registerHandler(wire::SshMessageType::ServiceRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::GlobalRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::RequestFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::Ignore, this);
  dispatcher.registerHandler(wire::SshMessageType::Debug, this);
  dispatcher.registerHandler(wire::SshMessageType::Unimplemented, this);
  dispatcher.registerHandler(wire::SshMessageType::Disconnect, this);

  user_auth_service_->registerMessageHandlers(*this);
  ping_handler_->registerMessageHandlers(*this);
  connection_service_->registerMessageHandlers(*this);

  user_auth_service_->registerMessageHandlers(*mgmt_client_);
  this->registerMessageHandlers(*mgmt_client_);
}

void SshServerTransport::registerMessageHandlers(
  MessageDispatcher<Grpc::ResponsePtr<ServerMessage>>& dispatcher) {
  dispatcher.registerHandler(ServerMessage::MessageCase::kStreamControl, this);
}

void SshServerTransport::setCodecCallbacks(Callbacks& callbacks) {
  TransportBase::setCodecCallbacks(callbacks);
  if (auto keys = openssh::loadHostKeys(codecConfig().host_keys()); !keys.ok()) {
    throw Envoy::EnvoyException(statusToString(keys.status()));
  } else {
    kex_->setHostKeys(std::move(*keys));
  }
  initServices();
  mgmt_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus, std::string err) {
    onDecodingFailure(absl::CancelledError(err));
  });
  stream_id_ = api_.randomGenerator().random();
  mgmt_client_->connect(streamId());
}

void SshServerTransport::initServices() {
  user_auth_service_ = std::make_unique<DownstreamUserAuthService>(*this, api_);
  connection_service_ = std::make_unique<DownstreamConnectionService>(*this, api_, tls_);
  ping_handler_ = std::make_unique<DownstreamPingExtensionHandler>(*this);

  service_names_.insert(user_auth_service_->name());
  service_names_.insert(connection_service_->name());
}

GenericProxy::EncodingResult SshServerTransport::encode(const GenericProxy::StreamFrame& frame,
                                                        GenericProxy::EncodingContext& /*ctx*/) {
  auto tags = frame.frameFlags().frameTags();
  switch (tags & FrameTags::FrameEffectiveTypeMask) {
  [[likely]]
  case FrameTags::EffectiveCommon:
    return sendMessageToConnection(extractFrameMessage(frame));
  case FrameTags::EffectiveHeader: {
    if (authState().handoff_info.handoff_in_progress) {
      authState().handoff_info.handoff_in_progress = false;
      callbacks_->connection()->readDisable(false);
    }
    if ((tags & FrameTags::Sentinel) != 0) {
      return 0;
    }
    if (authState().upstream_ext_info.has_value() &&
        authState().upstream_ext_info->hasExtension<wire::PingExtension>()) {
      // if the upstream supports the ping extension, we should forward pings to the upstream
      // instead of handling them ourselves
      ping_handler_->enableForward(true);
    }

    return sendMessageToConnection(extractFrameMessage(frame));
  } break;
  }
  PANIC("invalid frame tags");
}

GenericProxy::ResponsePtr SshServerTransport::respond(absl::Status status,
                                                      absl::string_view data,
                                                      const Request& req) {
  if (!status.ok()) {
    // something went wrong, send a disconnect message

    int code{};
    // check envoy well-known messages
    // TODO: possible to access core response flags from here?
    auto msg = status.message();
    if (msg == "cluster_not_found" || msg == "route_not_found") {
      code = SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT;
    } else if (msg == "cluster_maintain_mode" || msg == "no_healthy_upstream" || msg == "connection_failure" || msg == "overflow") {
      code = SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE;
    } else if (msg == "timeout" || msg == "local_reset" || msg == "connection_termination") {
      code = SSH2_DISCONNECT_CONNECTION_LOST;
    } else if (msg == "protocol_error") {
      code = SSH2_DISCONNECT_PROTOCOL_ERROR;
    } else {
      code = SSH2_DISCONNECT_BY_APPLICATION;
    }
    wire::DisconnectMsg dc;
    dc.reason_code = static_cast<uint32_t>(code);
    dc.description = statusToString(status);
    if (!data.empty()) {
      dc.description->append(fmt::format(" [{}]", data));
    }
    auto frame = std::make_unique<SSHResponseHeaderFrame>(std::move(dc), EffectiveCommon);
    frame->setStreamId(req.frameFlags().streamId());
    return frame;
  }
  PANIC("unimplemented");
}

absl::Status SshServerTransport::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceRequestMsg& msg) {
      if (service_names_.contains(msg.service_name)) {
        wire::ServiceAcceptMsg accept;
        accept.service_name = msg.service_name;
        return sendMessageToConnection(std::move(accept)).status();
      } else {
        return absl::UnavailableError("service not available");
      }
      ENVOY_LOG(debug, "received SshMessageType::ServiceRequest");
      return absl::OkStatus();
    },
    [&](wire::GlobalRequestMsg& msg) {
      auto stat = msg.request.visit(
        [&](wire::HostKeysProveRequestMsg& msg) {
          auto resp = handleHostKeysProve(msg);
          if (!resp.ok()) {
            return statusf("error handling HostKeysProveRequest: {}", resp.status());
          }
          wire::GlobalRequestSuccessMsg success;
          success.response = **resp;
          return sendMessageToConnection(std::move(success)).status();
        },
        [](wire::HostKeysMsg&) {
          ENVOY_LOG(warn, "received hostkeys-00@openssh.com (ignoring)");
          // ignore this for now
          return absl::OkStatus();
        },
        [&msg](auto&) {
          ENVOY_LOG(warn, "ignoring global request {}", msg.request_name());
          return absl::OkStatus();
        });
      if (!stat.ok()) {
        return stat;
      }
      forward(std::move(msg));

      return absl::OkStatus();
    },
    [&](any_of<wire::GlobalRequestSuccessMsg,
               wire::GlobalRequestFailureMsg,
               wire::IgnoreMsg,
               wire::DebugMsg,
               wire::UnimplementedMsg> auto& msg) {
      forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::DisconnectMsg& msg) {
      ENVOY_LOG(info, "received disconnect: {}", msg.description);
      return absl::CancelledError(fmt::format("received disconnect: {}", msg.description));
    },
    [](auto&) {
      ENVOY_LOG(warn, "unknown message");
      return absl::OkStatus();
    });
}

absl::Status SshServerTransport::handleMessage(Grpc::ResponsePtr<ServerMessage>&& msg) {
  switch (msg->message_case()) {
  case ServerMessage::kStreamControl:
    switch (msg->stream_control().action_case()) {
    case pomerium::extensions::ssh::StreamControl::kCloseStream: {
      return absl::CancelledError(msg->stream_control().close_stream().reason());
    }
    default:
      PANIC("unknown action case");
    }
  default:
    PANIC("unknown message case");
  }
}

void SshServerTransport::initUpstream(AuthStateSharedPtr s) {
  s->server_version = server_version_;
  auth_state_ = s;
  switch (auth_state_->channel_mode) {
  case ChannelMode::Normal: {
    auto frame = std::make_unique<SSHRequestHeaderFrame>(auth_state_);
    callbacks_->onDecodingSuccess(std::move(frame));

    ClientMessage upstream_connect_msg{};
    upstream_connect_msg.mutable_event()->mutable_upstream_connected()->set_stream_id(auth_state_->stream_id);
    sendMgmtClientMessage(upstream_connect_msg);
  } break;
  case ChannelMode::Hijacked: {
    if (auth_state_->allow_response->target_case() == pomerium::extensions::ssh::AllowResponse::kInternal) {
      const auto& internal = auth_state_->allow_response->internal();
      std::optional<envoy::config::core::v3::Metadata> optional_metadata;
      if (internal.has_set_metadata()) {
        optional_metadata = internal.set_metadata();
      }
      channel_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus code, std::string err) {
        // dynamic_cast<Envoy::Network::TransportSocketCallbacks&>(*callbacks_->connection()).flushWriteBuffer();
        runInNextIteration([=, this] {
          onDecodingFailure(absl::Status(static_cast<absl::StatusCode>(code), err));
        });
      });
      auth_state_->hijacked_stream = channel_client_->start(connection_service_.get(), std::move(optional_metadata));
      auto _ = sendMessageToConnection(wire::UserAuthSuccessMsg{});
    } else {
      ENVOY_LOG(error, "wrong target mode in AllowResponse for internal session");
      auto _ = sendMessageToConnection(wire::UserAuthFailureMsg{});
    }
  } break;
  case ChannelMode::Handoff: {
    channel_client_->setOnRemoteCloseCallback(nullptr);
    if (auto s = auth_state_->hijacked_stream.lock(); s) {
      s->resetStream();
    }
    auto frame = std::make_unique<SSHRequestHeaderFrame>(auth_state_);
    callbacks_->connection()->readDisable(true);
    callbacks_->onDecodingSuccess(std::move(frame));

    ClientMessage upstream_connect_msg{};
    upstream_connect_msg.mutable_event()->mutable_upstream_connected()->set_stream_id(auth_state_->stream_id);
    sendMgmtClientMessage(upstream_connect_msg);
  } break;
  case ChannelMode::Mirror:
    break;
  }
  if (auth_state_->multiplexing_info.multiplex_mode != MultiplexMode::None) {
    if (auto stat = connection_service_->onStreamBegin(*auth_state_, callbacks_->connection()->dispatcher()); !stat.ok()) {
      onDecodingFailure(stat);
      return;
    }
    callbacks_->connection()->addConnectionCallbacks(*this);
  }
}

absl::StatusOr<bytes> SshServerTransport::signWithHostKey(bytes_view in) const {
  auto hostKey = kex_result_->algorithms.host_key;
  if (auto k = kex_->getHostKey(openssh::SSHKey::keyTypeFromName(hostKey)); k) {
    return k->sign(in);
  }
  return absl::InternalError("no such host key");
}

const AuthState& SshServerTransport::authState() const {
  return *auth_state_;
}

AuthState& SshServerTransport::authState() {
  return *auth_state_;
}

void SshServerTransport::forward(wire::Message&& message, [[maybe_unused]] FrameTags tags) {
  auto frame = std::make_unique<SSHRequestCommonFrame>(std::move(message));
  frame->setStreamId(streamId());
  callbacks_->onDecodingSuccess(std::move(frame));
}

void SshServerTransport::onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) {
  TransportBase::onKexCompleted(std::move(kex_result), initial_kex);
  if (!initial_kex) {
    return;
  }

  // send ext_info if we have it and the client supports it (only after the initial key exchange)
  if (kex_result_->client_supports_ext_info) {
    auto extInfo = outgoingExtInfo();
    if (extInfo.has_value()) {
      (void)sendMessageToConnection(std::move(extInfo).value());
    }
  }
}

absl::StatusOr<std::unique_ptr<wire::HostKeysProveResponseMsg>>
SshServerTransport::handleHostKeysProve(const wire::HostKeysProveRequestMsg& msg) {
  std::vector<bytes> signatures;
  for (const auto& keyBlob : *msg.hostkeys) {
    auto key = openssh::SSHKey::fromPublicKeyBlob(keyBlob);
    if (!key.ok()) {
      return key.status();
    }
    auto hostKey = kex_->getHostKey((*key)->keyType());
    if (hostKey == nullptr || **key != *hostKey) {
      // not our key?
      ENVOY_LOG(error, "client requested to prove ownership of a key that isn't ours");
      return absl::InvalidArgumentError("requested key is invalid");
    }
    Envoy::Buffer::OwnedImpl tmp;
    wire::write_opt<wire::LengthPrefixed>(tmp, "hostkeys-prove-00@openssh.com"s);
    wire::write_opt<wire::LengthPrefixed>(tmp, kex_result_->session_id);
    wire::write_opt<wire::LengthPrefixed>(tmp, keyBlob);
    auto sig = (*key)->sign(wire::flushTo<bytes>(tmp));
    if (!sig.ok()) {
      return statusf("sshkey_sign failed: {}", sig.status());
    }
    signatures.push_back(std::move(*sig));
  }
  auto resp = std::make_unique<wire::HostKeysProveResponseMsg>();
  resp->signatures = std::move(signatures);
  return resp;
}

void SshServerTransport::sendMgmtClientMessage(const ClientMessage& msg) {
  mgmt_client_->stream().sendMessage(msg, false);
}

void SshServerTransport::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::LocalClose || event == Network::ConnectionEvent::RemoteClose) {
    connection_service_->onStreamEnd();
  }
}

void SshServerTransport::onDecodingFailure(absl::Status status) {
  wire::DisconnectMsg msg;
  msg.reason_code = SSH2_DISCONNECT_BY_APPLICATION;
  if (!status.ok()) {
    msg.description = statusToString(status);
  }
  (void)sendMessageToConnection(std::move(msg));

  TransportBase::onDecodingFailure(status);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec