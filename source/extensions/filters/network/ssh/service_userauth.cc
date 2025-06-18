#include "source/extensions/filters/network/ssh/service_userauth.h"

#include <cstdlib>
#include <memory>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

const std::vector<key_params_t> SupportedUpstreamKeyParams = {
  {"ssh-ed25519-cert-v01@openssh.com", KEY_ED25519, 256},
  {"ecdsa-sha2-nistp256-cert-v01@openssh.com", KEY_ECDSA, 256},
  {"ecdsa-sha2-nistp384-cert-v01@openssh.com", KEY_ECDSA, 384},
  {"ecdsa-sha2-nistp521-cert-v01@openssh.com", KEY_ECDSA, 521},
  {"rsa-sha2-512-cert-v01@openssh.com", KEY_RSA, 2048},
  {"rsa-sha2-256-cert-v01@openssh.com", KEY_RSA, 2048},
};
const key_params_t DefaultUpstreamKeyParams = SupportedUpstreamKeyParams[0];

void DownstreamUserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::UserAuthRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthInfoResponse, this);
  msg_dispatcher_ = dispatcher;
}

void DownstreamUserAuthService::registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(ServerMessage::kAuthResponse, this);
}

std::pair<std::string_view, std::string_view> detail::splitUsername(std::string_view in) {
  auto lastIndex = in.find_last_of('@');
  if (lastIndex == std::string::npos) {
    return {in, ""};
  }
  return {in.substr(0, lastIndex), in.substr(lastIndex + 1)};
}

absl::Status DownstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::UserAuthRequestMsg& msg) {
      if (!msg.request.has_value()) {
        ENVOY_LOG(debug, "unsupported user auth request {}", msg.method_name());
        return absl::UnimplementedError("unknown or unsupported auth method");
      }
      if (!pending_service_auth_.has_value()) {
        ENVOY_LOG(debug, "starting user auth for service: {}", msg.service_name);
        pending_service_auth_ = msg.service_name;
      } else if (pending_service_auth_ != msg.service_name) {
        return absl::FailedPreconditionError("inconsistent service names sent in user auth request");
      }

      auto [username, hostname] = detail::splitUsername(*msg.username);
      AuthenticationRequest auth_req;
      auth_req.set_protocol("ssh");
      auth_req.set_service(msg.service_name);
      auth_req.set_auth_method(msg.method_name());
      auth_req.set_hostname(hostname);
      auth_req.set_username(username);

      return msg.request.visit(
        [&](const wire::PubKeyUserAuthRequestMsg& pubkey_req) {
          auto userPubKey = openssh::SSHKey::fromPublicKeyBlob(pubkey_req.public_key);
          if (!userPubKey.ok()) {
            return userPubKey.status();
          }
          if ((!pubkey_req.signature->empty()) != pubkey_req.has_signature) {
            return absl::InvalidArgumentError(pubkey_req.has_signature
                                                ? "invalid PubKeyUserAuthRequestMsg: empty signature"
                                                : "invalid PubKeyUserAuthRequestMsg: unexpected signature");
          }
          if (!pubkey_req.has_signature) {
            // any public key is acceptable
            wire::UserAuthPubKeyOkMsg pubkey_ok;
            pubkey_ok.public_key_alg = pubkey_req.public_key_alg;
            pubkey_ok.public_key = pubkey_req.public_key;
            return transport_.sendMessageToConnection(std::move(pubkey_ok)).status();
          }

          // verify the signature
          {
            // RFC4252 § 7
            Envoy::Buffer::OwnedImpl verifyBuf;
            wire::write_opt<wire::LengthPrefixed>(verifyBuf, transport_.sessionId());
            if (auto r = wire::encodeMsg(verifyBuf, msg.type,
                                         msg.username,
                                         msg.service_name,
                                         msg.request.key_field(),
                                         pubkey_req.has_signature,
                                         pubkey_req.public_key_alg,
                                         pubkey_req.public_key);
                !r.ok()) {
              return absl::InternalError(statusToString(r.status()));
            }
            auto verifyBytes = wire::flushTo<bytes>(verifyBuf);
            if (auto stat = (*userPubKey)->verify(*pubkey_req.signature, verifyBytes, *pubkey_req.public_key_alg); !stat.ok()) {
              return stat;
            }
          }

          // forward the request to pomerium
          PublicKeyMethodRequest method_req;
          method_req.set_public_key(pubkey_req.public_key->data(), pubkey_req.public_key->size());
          method_req.set_public_key_alg(pubkey_req.public_key_alg);
          auth_req.mutable_method_request()->PackFrom(method_req);

          pomerium::extensions::ssh::ClientMessage clientMsg;
          *clientMsg.mutable_auth_request() = auth_req;
          transport_.sendMgmtClientMessage(clientMsg);

          return absl::OkStatus();
        },
        [&](const wire::KeyboardInteractiveUserAuthRequestMsg& interactive_req) {
          KeyboardInteractiveMethodRequest method_req;
          for (const auto& sm : *interactive_req.submethods) {
            method_req.add_submethods(sm);
          }
          auth_req.mutable_method_request()->PackFrom(method_req);

          pomerium::extensions::ssh::ClientMessage clientMsg;
          *clientMsg.mutable_auth_request() = auth_req;
          transport_.sendMgmtClientMessage(clientMsg);

          return absl::OkStatus();
        },
        [&](const wire::NoneAuthRequestMsg&) {
          if (none_auth_handled_) {
            // "none" auth is only allowed once
            return absl::InvalidArgumentError("invalid auth request");
          }
          none_auth_handled_ = true;
          wire::UserAuthFailureMsg failure;
          failure.methods = {"publickey"s};
          return transport_.sendMessageToConnection(std::move(failure)).status();
        });
    },
    [&](opt_ref<wire::UserAuthInfoResponseMsg> opt_msg) {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid auth response");
      }
      // SSH_MSG_USERAUTH_INFO_RESPONSE is sent only for the keyboard-interactive method.
      auto& msg = opt_msg->get();
      InfoResponse info_resp;
      info_resp.set_method("keyboard-interactive");
      KeyboardInteractiveInfoPromptResponses info_method_resp;
      for (const auto& resp : *msg.responses) {
        info_method_resp.add_responses(resp);
      }
      info_resp.mutable_response()->PackFrom(info_method_resp);

      pomerium::extensions::ssh::ClientMessage clientMsg;
      *clientMsg.mutable_info_response() = info_resp;
      transport_.sendMgmtClientMessage(clientMsg);

      return absl::OkStatus();
    },
    [&msg](auto&) {
      return absl::InternalError(
        fmt::format("received unexpected message of type {}", msg.msg_type()));
    });
}

absl::Status DownstreamUserAuthService::handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) {
  switch (message->message_case()) {
  case pomerium::extensions::ssh::ServerMessage::kAuthResponse: {
    auto authResp = message->auth_response();
    switch (authResp.response_case()) {
    case AuthenticationResponse::kAllow: {
      auto allow = authResp.allow();
      auto state = std::make_shared<AuthState>();
      state->allow_response = std::make_unique<AllowResponse>();
      state->allow_response->CopyFrom(allow);
      state->stream_id = transport_.streamId();
      state->downstream_ext_info = transport_.peerExtInfo();
      switch (allow.target_case()) {
      case pomerium::extensions::ssh::AllowResponse::kUpstream:
        state->channel_mode = ChannelMode::Normal;
#ifdef SSH_EXPERIMENTAL
        state->multiplexing_info = MultiplexingInfo{};
        if (allow.upstream().allow_mirror_connections()) {
          state->multiplexing_info.multiplex_mode = MultiplexMode::Source;
        }
#endif
        break;
      case pomerium::extensions::ssh::AllowResponse::kInternal:
        state->channel_mode = ChannelMode::Hijacked;
        break;
#ifdef SSH_EXPERIMENTAL
      case pomerium::extensions::ssh::AllowResponse::kMirrorSession: {
        transport_.sendMessageToConnection(wire::UserAuthSuccessMsg())
          .IgnoreError();
        const auto& mirror = state->allow_response->mirror_session();
        state->multiplexing_info.multiplex_mode = MultiplexMode::Mirror;
        state->channel_mode = ChannelMode::Mirror;
        switch (mirror.mode()) {
        case pomerium::extensions::ssh::MirrorSessionTarget::READ_ONLY:
          state->multiplexing_info.rw_mode = ReadWriteMode::ReadOnly;
          break;
        case pomerium::extensions::ssh::MirrorSessionTarget::READ_WRITE:
          state->multiplexing_info.rw_mode = ReadWriteMode::ReadWrite;
          break;
        default:
          return absl::InvalidArgumentError("unknown mode");
        }
        state->multiplexing_info.source_stream_id = mirror.source_id();
      } break;
#endif
      default:
        return absl::InternalError("invalid target");
      }
      RELEASE_ASSERT(pending_service_auth_.has_value(), "no service is pending auth");
      transport_.onServiceAuthenticated(*std::move(pending_service_auth_));
      transport_.initUpstream(std::move(state));
      msg_dispatcher_->unregisterHandler(this);

      return absl::OkStatus();
    }
    case AuthenticationResponse::kDeny: {
      const auto& deny = authResp.deny();
      auto methods = deny.methods();
      if (methods.empty()) {
        return absl::PermissionDeniedError("");
      }
      if (!deny.partial()) {
        auth_failure_count_++;
        if (auth_failure_count_ >= MaxFailedAuthAttempts) {
          ENVOY_LOG(warn, "max auth attempts exceeded, disconnecting");
          return absl::PermissionDeniedError("too many authentication failures");
        }
      }
      wire::UserAuthFailureMsg failure;
      failure.partial = deny.partial();
      failure.methods = string_list(methods.begin(), methods.end());
      return transport_.sendMessageToConnection(std::move(failure)).status();
    }
    case AuthenticationResponse::kInfoRequest: {
      const auto& infoReq = authResp.info_request();
      if (infoReq.method() == "keyboard-interactive") {
        KeyboardInteractiveInfoPrompts server_req;
        infoReq.request().UnpackTo(&server_req);

        wire::UserAuthInfoRequestMsg client_req;
        client_req.name = server_req.name();
        client_req.instruction = server_req.instruction();
        for (const auto& prompt : server_req.prompts()) {
          wire::UserAuthInfoPrompt p;
          p.prompt = prompt.prompt();
          p.echo = prompt.echo();
          client_req.prompts->push_back(std::move(p));
        }
        return transport_.sendMessageToConnection(std::move(client_req)).status();
      }
      return absl::InvalidArgumentError("unknown method");
    }
    default:
      return absl::InternalError("server sent invalid response case");
    }
  }
  default:
    return absl::InternalError("server sent invalid message case");
  }
}

UpstreamUserAuthService::UpstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : UserAuthService(callbacks, api) {
  {
    auto privKey = openssh::SSHKey::fromPrivateKeyDataSource(transport_.codecConfig().user_ca_key());
    THROW_IF_NOT_OK_REF(privKey.status());
    ca_user_key_ = std::move(*privKey);
  }
}

void UpstreamUserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::UserAuthBanner, this);
  dispatcher.registerHandler(wire::SshMessageType::ExtInfo, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthFailure, this);
  msg_dispatcher_ = dispatcher;
}

absl::Status UpstreamUserAuthService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(std::move(req)).status();
}

key_params_t UpstreamUserAuthService::getUpstreamKeyParams() {
  auto key_params = DefaultUpstreamKeyParams;

  auto ext_info = transport_.peerExtInfo();
  if (ext_info) {
    auto server_sig_algs = ext_info->getExtension<wire::ServerSigAlgsExtension>();
    if (server_sig_algs) {
      auto v = *server_sig_algs->public_key_algorithms_accepted;
      absl::flat_hash_set<std::string> server_algs(v.begin(), v.end());
      for (const auto& p : SupportedUpstreamKeyParams) {
        auto alg = std::get<0>(p);
        auto plain_alg = openssh::certSigningAlgorithmToPlain(alg);
        if (server_algs.contains(alg) ||
            (plain_alg.has_value() && server_algs.contains(*plain_alg))) {
          key_params = p;
          break;
        }
      }
    }
  }

  return key_params;
}

absl::Status UpstreamUserAuthService::onServiceAccepted() {
  if (!transport_.authState().allow_response) {
    return absl::InternalError("missing AllowResponse in auth state");
  }

  auto [alg, key_type, key_bits] = getUpstreamKeyParams();

  auto res = openssh::SSHKey::generate(key_type, key_bits);
  RELEASE_ASSERT(res.ok(), fmt::format("couldn't generate ephemeral ssh key: {}", res.status()));
  auto userSessionSshKey = std::move(res).value();
  auto stat = userSessionSshKey->convertToSignedUserCertificate(
    1,
    {transport_.authState().allow_response->username()},
    {
      openssh::ExtensionNoTouchRequired,
      openssh::ExtensionPermitX11Forwarding,
      openssh::ExtensionPermitPortForwarding,
      openssh::ExtensionPermitPty,
      openssh::ExtensionPermitUserRc,
    },
    absl::Hours(24),
    *ca_user_key_);
  RELEASE_ASSERT(res.ok(), fmt::format("error generating user certificate: {}", stat));

  auto req = std::make_unique<wire::UserAuthRequestMsg>();
  req->username = transport_.authState().allow_response->username();
  req->service_name = "ssh-connection";

  wire::PubKeyUserAuthRequestMsg pubkeyReq{
    .has_signature = true,
    .public_key_alg = alg,
    .public_key = userSessionSshKey->toPublicKeyBlob(),
  };

  // compute signature
  Envoy::Buffer::OwnedImpl buf;
  wire::write_opt<wire::LengthPrefixed>(buf, transport_.sessionId());
  constexpr static wire::field<std::string, wire::LengthPrefixed> method_name =
    std::string(wire::PubKeyUserAuthRequestMsg::submsg_key);
  if (auto r = wire::encodeMsg(buf, req->type,
                               req->username,
                               req->service_name,
                               method_name,
                               pubkeyReq.has_signature,
                               pubkeyReq.public_key_alg,
                               pubkeyReq.public_key);
      !r.ok()) {
    return statusf("error encoding user auth request: {}", r.status());
  }
  auto sig = userSessionSshKey->sign(wire::flushTo<bytes>(buf), alg);
  RELEASE_ASSERT(sig.ok(), fmt::format("error signing user auth request: {}", sig.status()));
  pubkeyReq.signature = *sig;

  req->request = std::move(pubkeyReq);
  pending_req_ = std::move(req);

  return transport_.sendMessageToConnection(auto(*pending_req_)).status();
}

absl::Status UpstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::UserAuthBannerMsg& msg) {
      // If the downstream is in the auth flow, we can simply forward this along
      if (transport_.authState().channel_mode == ChannelMode::Normal) {
        transport_.forward(std::move(msg));
      }
      return absl::OkStatus();
    },
    [&](wire::ExtInfoMsg& msg) {
      if (ext_info_received_) {
        return absl::FailedPreconditionError("unexpected ExtInfoMsg received");
      }
      ext_info_received_ = true;
      transport_.updatePeerExtInfo(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::UserAuthSuccessMsg& msg) { // forward upstream success to downstream
      // this comment intentionally placed here for searchability ^
      if (!pending_req_) {
        return absl::FailedPreconditionError("unexpected UserAuthSuccessMsg received");
      }
      ENVOY_LOG(info, "user auth success: {} [{}]", pending_req_->username,
                pending_req_->method_name());
      if (auto info = transport_.peerExtInfo(); info.has_value()) {
        transport_.authState().upstream_ext_info = std::move(info);
      }

      pending_req_.reset();
      transport_.forwardHeader(std::move(msg));

      msg_dispatcher_->unregisterHandler(this);

      return absl::OkStatus();
    },
    [&](wire::UserAuthFailureMsg&) {
      return absl::PermissionDeniedError("");
    },
    [&msg](auto&) {
      return absl::InternalError(
        fmt::format("received unexpected message of type {}", msg.msg_type()));
    });
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec