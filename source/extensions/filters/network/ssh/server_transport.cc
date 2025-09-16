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
#include "source/extensions/filters/network/ssh/filter_state_objects.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

extern "C" {
#include "openssh/ssh2.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

SshServerTransport::SshServerTransport(Server::Configuration::ServerFactoryContext& context,
                                       std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                                       CreateGrpcClientFunc create_grpc_client,
                                       StreamTrackerSharedPtr stream_tracker)
    : TransportBase(context, std::move(config)),
      DownstreamTransportCallbacks(*this),
      stream_tracker_(std::move(stream_tracker)) {
  auto grpcClient = create_grpc_client();
  THROW_IF_NOT_OK_REF(grpcClient.status());
  grpc_client_ = *grpcClient;
  mgmt_client_ = std::make_unique<StreamManagementServiceClient>(grpc_client_);

  wire::ExtInfoMsg extInfo;
  extInfo.extensions->emplace_back(wire::PingExtension{.version = "0"s});
  extInfo.extensions->emplace_back(wire::ExtInfoInAuthExtension{.version = "0"s});
  extInfo.extensions->emplace_back(wire::ServerSigAlgsExtension{
    .public_key_algorithms_accepted = SupportedSigningAlgorithms,
  });
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

  ping_handler_->registerMessageHandlers(*this);
  user_auth_service_->registerMessageHandlers(*mgmt_client_);
}

void SshServerTransport::setCodecCallbacks(Callbacks& callbacks) {
  TransportBase::setCodecCallbacks(callbacks);
  if (auto keys = openssh::loadHostKeys(codecConfig().host_keys()); !keys.ok()) {
    throw Envoy::EnvoyException(statusToString(keys.status()));
  } else {
    kex_->setHostKeys(std::move(*keys));
  }
}

void SshServerTransport::onConnected() {
  auto& conn = *callbacks_->connection();

  ASSERT(conn.state() == Network::Connection::State::Open);
  connection_dispatcher_ = conn.dispatcher();
  channel_id_manager_ = std::make_shared<ChannelIDManager>();
  conn.streamInfo().filterState()->setData(ChannelIDManagerFilterStateKey,
                                           channel_id_manager_,
                                           StreamInfo::FilterState::StateType::Mutable,
                                           StreamInfo::FilterState::LifeSpan::Request,
                                           StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
  initServices();
  mgmt_client_->setOnRemoteCloseCallback([this](Grpc::Status::GrpcStatus, std::string err) {
    terminate(absl::CancelledError(err));
  });
  stream_id_ = api_.randomGenerator().random();
  mgmt_client_->connect(streamId());
}

void SshServerTransport::initServices() {
  user_auth_service_ = std::make_unique<DownstreamUserAuthService>(*this, api_);
  connection_service_ = std::make_unique<DownstreamConnectionService>(*this, stream_tracker_);
  ping_handler_ = std::make_unique<PingExtensionHandler>(*this);

  services_[user_auth_service_->name()] = user_auth_service_.get();
  services_[connection_service_->name()] = connection_service_.get();
}

GenericProxy::EncodingResult SshServerTransport::encode(const GenericProxy::StreamFrame& frame,
                                                        GenericProxy::EncodingContext& /*ctx*/) {
  auto tags = frame.frameFlags().frameTags();
  if ((tags & FrameTags::FrameEffectiveTypeMask) == FrameTags::EffectiveCommon) [[likely]] {
    return sendMessageToConnection(extractFrameMessage(frame));
  }
  ASSERT((tags & FrameTags::FrameEffectiveTypeMask) == FrameTags::EffectiveHeader); // 1-bit mask
  if (authInfo().handoff_info.handoff_in_progress) {
    ENVOY_LOG(debug, "handoff complete, re-enabling reads on downstream connection");
    authInfo().handoff_info.handoff_in_progress = false;
    callbacks_->connection()->readDisable(false);
  }
  if ((tags & FrameTags::Sentinel) != 0) {
    return 0;
  }
  if (authInfo().upstream_ext_info.has_value() &&
      authInfo().upstream_ext_info->hasExtension<wire::PingExtension>()) {
    // if the upstream supports the ping extension, we should forward pings to the upstream
    // instead of handling them ourselves
    ping_handler_->enableForward(true);
  }

  return sendMessageToConnection(extractFrameMessage(frame));
}

GenericProxy::ResponsePtr SshServerTransport::respond(absl::Status status,
                                                      absl::string_view data,
                                                      const Request& req) {
  RELEASE_ASSERT(!status.ok(), "respond() called with OK status");

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
    dc.description->append(fmt::format(": [{}]", data));
  }
  auto frame = std::make_unique<SSHResponseHeaderFrame>(std::move(dc),
                                                        FrameTags(EffectiveCommon | Error));
  frame->setStreamId(req.frameFlags().streamId());
  return frame;
}

absl::Status SshServerTransport::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceRequestMsg& msg) {
      if (msg.service_name != "ssh-userauth") {
        return absl::InvalidArgumentError("invalid service name");
      }
      onServiceAuthenticated(msg.service_name);
      wire::ServiceAcceptMsg accept;
      accept.service_name = msg.service_name;
      // don't allow any further ServiceRequestMsgs
      unregisterHandler(msg.msg_type());
      return sendMessageToConnection(std::move(accept)).status();
    },
    [&](wire::GlobalRequestMsg& msg) {
      if (!msg.request.has_value()) { // unknown request
        if (!upstreamReady()) {
          return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
        }
        ENVOY_LOG(debug, "forwarding global request: {}", msg.request_name());
        forward(std::move(msg));
        return absl::OkStatus();
      }
      return msg.request.visit(
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
          // server->client only
          return absl::InvalidArgumentError(fmt::format("unexpected global request: {}",
                                                        wire::HostKeysMsg::submsg_key));
        },
        [&](wire::TcpipForwardMsg& forward_msg) {
          if (authInfo().channel_mode == ChannelMode::Hijacked) {
            ENVOY_LOG(debug, "sending global request to hijacked stream: {}", msg.request_name());
            ClientMessage clientMsg;
            auto* streamEvent = clientMsg.mutable_event();
            auto* globalReq = streamEvent->mutable_global_request();
            auto* forwardReq = globalReq->mutable_tcpip_forward_request();
            forwardReq->set_remote_address(forward_msg.remote_address);
            forwardReq->set_remote_port(forward_msg.remote_port);
            sendMgmtClientMessage(clientMsg);

            return absl::OkStatus();
          }

          ENVOY_LOG(debug, "forwarding global request: {}", msg.request_name());
          forward(std::move(msg));
          return absl::OkStatus();
        },
        [&](wire::CancelTcpipForwardMsg& forward_msg) {
          if (authInfo().channel_mode == ChannelMode::Hijacked) {
            ENVOY_LOG(debug, "sending global request to hijacked stream: {}", msg.request_name());
            ClientMessage clientMsg;
            auto* streamEvent = clientMsg.mutable_event();
            auto* globalReq = streamEvent->mutable_global_request();
            auto* forwardReq = globalReq->mutable_cancel_tcpip_forward_request();
            forwardReq->set_remote_address(forward_msg.remote_address);
            forwardReq->set_remote_port(forward_msg.remote_port);
            sendMgmtClientMessage(clientMsg);

            return absl::OkStatus();
          }

          ENVOY_LOG(debug, "forwarding global request: {}", msg.request_name());
          forward(std::move(msg));
          return absl::OkStatus();
        });
    },
    [&](wire::GlobalRequestSuccessMsg& msg) {
      // we currently don't send any global requests that require a response, so this would be
      // the result of an upstream request
      if (!upstreamReady()) {
        return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
      }
      forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::GlobalRequestFailureMsg& msg) {
      if (!upstreamReady()) {
        return absl::InvalidArgumentError(fmt::format("unexpected message received: {}", msg.msg_type()));
      }
      forward(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::IgnoreMsg&) {
      return absl::OkStatus();
    },
    [&](wire::DebugMsg& msg) {
      ENVOY_LOG(debug, "received DebugMsg: \"{}\"", msg.message);
      return absl::OkStatus();
    },
    [&](wire::UnimplementedMsg& msg) {
      ENVOY_LOG(debug, "received UnimplementedMsg for sequence number {} (ignoring)", msg.sequence_number);
      return absl::OkStatus();
    },
    [&](wire::DisconnectMsg& msg) {
      auto desc = *msg.description;
      auto logMsg = fmt::format("received disconnect: {}{}{}",
                                openssh::disconnectCodeToString(*msg.reason_code),
                                desc.empty() ? "" : ": ", desc);
      ENVOY_LOG(info, logMsg);
      return absl::CancelledError(logMsg);
    },
    [](auto& msg) {
      return absl::InternalError(fmt::format("received invalid message: {}", msg.msg_type()));
    });
}

void SshServerTransport::onServiceAuthenticated(const std::string& service_name) {
  RELEASE_ASSERT(services_.contains(service_name), fmt::format("unknown service: {}", service_name));
  ENVOY_LOG(debug, "service authenticated: {}", service_name);
  services_[service_name]->registerMessageHandlers(*this);
}

void SshServerTransport::initHandoff(pomerium::extensions::ssh::SSHChannelControlAction_HandOffUpstream* handoff_msg) {
  connection_service_->disableChannelHijack();
  auto newState = std::make_shared<AuthInfo>();
  newState->server_version = authInfo().server_version;
  newState->stream_id = authInfo().stream_id;
  newState->channel_mode = authInfo().channel_mode;
  switch (handoff_msg->upstream_auth().target_case()) {
  case pomerium::extensions::ssh::AllowResponse::kUpstream:
    newState->handoff_info.handoff_in_progress = true;
    newState->channel_mode = ChannelMode::Handoff;
    newState->allow_response.reset(handoff_msg->release_upstream_auth());
    if (handoff_msg->has_downstream_channel_info()) {
      newState->handoff_info.channel_info.reset(handoff_msg->release_downstream_channel_info());
    }
    if (handoff_msg->has_downstream_pty_info()) {
      newState->handoff_info.pty_info.reset(handoff_msg->release_downstream_pty_info());
    }
    ENVOY_LOG(debug, "starting handoff to upstream {} for internal channel {}",
              newState->allow_response->upstream().hostname(),
              newState->handoff_info.channel_info->internal_upstream_channel_id());
    initUpstream(std::move(newState));
    break;
  case pomerium::extensions::ssh::AllowResponse::kMirrorSession:
    terminate(absl::UnavailableError("session mirroring feature not available"));
    break;
  default:
    terminate(absl::InternalError(fmt::format("received invalid channel message: unexpected target: {}",
                                              static_cast<int>(handoff_msg->upstream_auth().target_case()))));
    break;
  }
}

void SshServerTransport::initUpstream(AuthInfoSharedPtr auth_info) {
  auth_info->server_version = server_version_;
  bool first_init = (auth_info_ == nullptr);
  auth_info_ = auth_info;
  callbacks_->connection()->streamInfo().filterState()->setData(
    AuthInfoFilterStateKey, auth_info_,
    StreamInfo::FilterState::StateType::Mutable,
    StreamInfo::FilterState::LifeSpan::Request,
    StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
  switch (auth_info_->channel_mode) {
  case ChannelMode::Normal: {
    ASSERT(auth_info_->allow_response != nullptr);
    auto frame = std::make_unique<SSHRequestHeaderFrame>(
      auth_info_->allow_response->upstream().hostname(),
      stream_id_,
      *callbacks_->connection()->streamInfo().filterState());
    callbacks_->onDecodingSuccess(std::move(frame));

    ClientMessage upstream_connect_msg{};
    upstream_connect_msg.mutable_event()->mutable_upstream_connected();
    sendMgmtClientMessage(upstream_connect_msg);
  } break;
  case ChannelMode::Hijacked: {
    ASSERT(auth_info_->allow_response != nullptr);
    RELEASE_ASSERT(auth_info_->allow_response->target_case() == pomerium::extensions::ssh::AllowResponse::kInternal,
                   "wrong target mode in AllowResponse for internal session");

    const auto& internal = auth_info_->allow_response->internal();
    connection_service_->enableChannelHijack(*this, internal, grpc_client_);

    sendMessageToConnection(wire::UserAuthSuccessMsg{})
      .IgnoreError();
  } break;
  case ChannelMode::Handoff: {
    auto frame = std::make_unique<SSHRequestHeaderFrame>(
      auth_info_->allow_response->upstream().hostname(),
      stream_id_,
      *callbacks_->connection()->streamInfo().filterState());
    ENVOY_LOG(debug, "disabling reads on downstream connection for handoff");
    callbacks_->connection()->readDisable(true);
    callbacks_->onDecodingSuccess(std::move(frame));

    ClientMessage upstream_connect_msg{};
    upstream_connect_msg.mutable_event()->mutable_upstream_connected();
    sendMgmtClientMessage(upstream_connect_msg);
  } break;
  case ChannelMode::Mirror:
    throw EnvoyException("mirroring not supported");
  }
  if (first_init) {
    connection_service_->onStreamBegin(callbacks_->connection().ref());
    callbacks_->connection()->addConnectionCallbacks(*this);
  }
}

AuthInfo& SshServerTransport::authInfo() {
  ASSERT(upstreamReady());
  return *auth_info_;
}

void SshServerTransport::forward(wire::Message&& message, [[maybe_unused]] FrameTags tags) {
  ASSERT(upstreamReady());
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
      sendMessageToConnection(std::move(extInfo).value())
        .IgnoreError();
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
    auto sig = hostKey->sign(wire::flushTo<bytes>(tmp));
    RELEASE_ASSERT(sig.ok(), fmt::format("sshkey_sign failed: {}", sig.status()));
    signatures.push_back(std::move(*sig));
  }
  auto resp = std::make_unique<wire::HostKeysProveResponseMsg>();
  resp->signatures = std::move(signatures);
  return resp;
}

void SshServerTransport::sendMgmtClientMessage(const ClientMessage& msg) {
  ASSERT(msg.message_case() != ClientMessage::MessageCase::MESSAGE_NOT_SET, "empty ClientMessage sent");
  mgmt_client_->stream().sendMessage(msg, false);
}

void SshServerTransport::terminate(absl::Status status) {
  wire::DisconnectMsg msg;
  msg.reason_code = openssh::statusCodeToDisconnectCode(status.code());
  msg.description = statusToString(status);
  sendMessageToConnection(std::move(msg))
    .IgnoreError();

  TransportBase::terminate(status);
}

void SshServerTransport::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::LocalClose || event == Network::ConnectionEvent::RemoteClose) {
    connection_service_->onStreamEnd();
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec