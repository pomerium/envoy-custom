#include "source/extensions/filters/network/ssh/service_userauth.h"

#include <cstdlib>
#include <memory>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  {
    auto privKey = openssh::SSHKey::fromPrivateKeyFile(transport_.codecConfig().user_ca_key());
    THROW_IF_NOT_OK_REF(privKey.status());
    ca_user_key_ = std::move(*privKey);
  }
}

void UserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::UserAuthRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthPubKeyOk, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthBanner, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthInfoResponse, this);
  dispatcher.registerHandler(wire::SshMessageType::ExtInfo, this);
  msg_dispatcher_ = dispatcher;
}

void DownstreamUserAuthService::registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(ServerMessage::kAuthResponse, this);
}

absl::Status UserAuthService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(std::move(req)).status();
}

static std::pair<std::string_view, std::string_view> splitUsername(std::string_view in) {
  if (in.contains("://")) {
    return {in, ""};
  }
  auto lastIndex = in.find_last_of('@');
  if (lastIndex == std::string::npos) {
    return {in, ""};
  }
  return {in.substr(0, lastIndex), in.substr(lastIndex + 1)};
}

absl::Status DownstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::UserAuthRequestMsg& msg) {
      auto [username, hostname] = splitUsername(*msg.username);
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
          // wire::UserAuthBannerMsg banner{};
          // auto fingerprint = userPubKey->fingerprint();
          // if (!fingerprint.ok()) {
          //   return fingerprint.status();
          // }
          // banner.message = fmt::format(
          //   "\n====== TEST BANNER ======"
          //   "\nmethod:   {}"
          //   "\nusername: {}"
          //   "\nhostname: {}"
          //   "\nkeyalg:   {}"
          //   "\npubkey:   {}"
          //   "\nsession:  {}"
          //   "\n=========================\n",
          //   msg.method_name, username, hostname,
          //   pubkey_req.public_key_alg, *fingerprint, transport_.streamId());
          // auto _ = transport_.sendMessageToConnection(banner);

          if ((!pubkey_req.signature->empty()) != pubkey_req.has_signature) {
            return absl::InvalidArgumentError(pubkey_req.has_signature
                                                ? "invalid message: missing signature"
                                                : "invalid message: unexpected signature");
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
            // RFC4242 § 7
            Envoy::Buffer::OwnedImpl verifyBuf;
            wire::write_opt<wire::LengthPrefixed>(verifyBuf, transport_.sessionId());
            constexpr static wire::field<bool> has_signature = true;
            if (auto r = wire::encodeMsg(verifyBuf, msg.type,
                                         msg.username,
                                         msg.service_name,
                                         msg.request.key_field(),
                                         has_signature,
                                         pubkey_req.public_key_alg,
                                         pubkey_req.public_key);
                !r.ok()) {
              return absl::InternalError(statusToString(r.status()));
            }
            auto verifyBytes = wire::flushTo<bytes>(verifyBuf);
            if (auto stat = (*userPubKey)->verify(*pubkey_req.signature, verifyBytes); !stat.ok()) {
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
          wire::UserAuthFailureMsg failure;
          failure.methods = {"publickey"s};
          return transport_.sendMessageToConnection(std::move(failure)).status();
        },
        [&](const auto&) {
          ENVOY_LOG(debug, "unsupported user auth request {}", msg.method_name());
          return absl::UnimplementedError("unknown or unsupported auth method");
        });
    },
    [&](opt_ref<wire::UserAuthInfoResponseMsg> opt_msg) {
      if (!opt_msg.has_value()) {
        return absl::InvalidArgumentError("invalid auth response");
      }
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
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
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
        state->multiplexing_info = MultiplexingInfo{};
        if (allow.upstream().allow_mirror_connections()) {
          state->multiplexing_info.multiplex_mode = MultiplexMode::Source;
        }
        break;
      case pomerium::extensions::ssh::AllowResponse::kInternal:
        state->channel_mode = ChannelMode::Hijacked;
        break;
      case pomerium::extensions::ssh::AllowResponse::kMirrorSession: {
        auto _ = transport_.sendMessageToConnection(wire::UserAuthSuccessMsg());
        const auto& mirror = state->allow_response->mirror_session();
        state->multiplexing_info.multiplex_mode = MultiplexMode::Mirror;
        state->channel_mode = ChannelMode::Mirror;
        switch (mirror.mode()) {
        case pomerium::extensions::ssh::MirrorSessionTarget_Mode_ReadOnly:
          state->multiplexing_info.rw_mode = ReadWriteMode::ReadOnly;
          break;
        case pomerium::extensions::ssh::MirrorSessionTarget_Mode_ReadWrite:
          state->multiplexing_info.rw_mode = ReadWriteMode::ReadWrite;
          break;
        default:
          return absl::InvalidArgumentError("unknown mode");
        }
        state->multiplexing_info.source_stream_id = mirror.source_id();
      } break;
      default:
        return absl::InternalError("invalid target");
      }
      transport_.initUpstream(std::move(state));
      return absl::OkStatus();
    }
    case AuthenticationResponse::kDeny: {
      const auto& deny = authResp.deny();
      auto methods = deny.methods();
      if (methods.empty()) {
        return absl::PermissionDeniedError("");
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
      PANIC("server sent invalid response case");
    }
  }
  default:
    PANIC("server sent invalid message case");
  }
}

absl::StatusOr<MiddlewareResult> UpstreamUserAuthService::interceptMessage(wire::Message& msg) {
  if (msg.msg_type() != wire::SshMessageType::UserAuthSuccess) {
    return absl::FailedPreconditionError("received out-of-order ExtInfo message during auth");
  }
  return Continue | UninstallSelf;
}

absl::Status UpstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceAcceptMsg&) {
      if (!transport_.authState().allow_response) {
        return absl::InternalError("missing AllowResponse in auth state");
      }
      auto res = openssh::SSHKey::generate(KEY_ED25519, 256);
      if (!res.ok()) {
        return res.status();
      }
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
      if (!stat.ok()) {
        return statusf("error generating user certificate: {}", stat);
      }

      auto req = std::make_unique<wire::UserAuthRequestMsg>();
      req->username = transport_.authState().allow_response->username();
      req->service_name = "ssh-connection";

      wire::PubKeyUserAuthRequestMsg pubkeyReq;
      pubkeyReq.has_signature = false;
      pubkeyReq.public_key_alg = "ssh-ed25519-cert-v01@openssh.com";

      auto blob = userSessionSshKey->toPublicKeyBlob();
      if (!blob.ok()) {
        return statusf("error serializing user session key: {}", blob.status());
      }
      pubkeyReq.public_key = *blob;
      req->request = std::move(pubkeyReq);
      pending_req_ = std::move(req);
      pending_user_key_ = std::move(userSessionSshKey);

      return transport_.sendMessageToConnection(auto(*pending_req_)).status();
    },
    [&](opt_ref<wire::UserAuthPubKeyOkMsg> opt_msg) {
      if (!opt_msg.has_value() || !pending_req_) {
        return absl::FailedPreconditionError("invalid auth response");
      }
      // compute signature
      Envoy::Buffer::OwnedImpl buf;
      wire::write_opt<wire::LengthPrefixed>(buf, transport_.sessionId());
      auto& pending_pk_req = pending_req_->request.get<wire::PubKeyUserAuthRequestMsg>();
      constexpr static wire::field<bool> has_signature = true;
      if (auto r = wire::encodeMsg(buf, pending_req_->type,
                                   pending_req_->username,
                                   pending_req_->service_name,
                                   pending_req_->request.key_field(),
                                   has_signature,
                                   pending_pk_req.public_key_alg,
                                   pending_pk_req.public_key);
          !r.ok()) {
        return statusf("error encoding user auth request: {}", r.status());
      }
      auto sig = pending_user_key_->sign(wire::flushTo<bytes>(buf));
      if (!sig.ok()) {
        return statusf("error signing user auth request: {}", sig.status());
      }
      pending_pk_req.has_signature = true;
      pending_pk_req.signature = *sig;
      return transport_.sendMessageToConnection(auto(*pending_req_)).status();
    },
    [&](wire::UserAuthBannerMsg& msg) {
      // If the downstream is in the auth flow, we can simply forward this along
      if (transport_.authState().channel_mode == ChannelMode::Normal) {
        transport_.forward(std::move(msg));
      }
      return absl::OkStatus();
    },
    [&](wire::ExtInfoMsg& msg) {
      if (auth_success_received_ || ext_info_.has_value()) {
        return absl::FailedPreconditionError("unexpected ExtInfoMsg received");
      }
      ext_info_ = std::move(msg);
      msg_dispatcher_->installMiddleware(this);
      return absl::OkStatus();
    },
    [&](wire::UserAuthSuccessMsg& msg) { // forward upstream success to downstream
      // this comment intentionally placed here for searchability ^
      ENVOY_LOG(info, "user auth success: {} [{}]", pending_req_->username,
                pending_req_->method_name());
      if (ext_info_.has_value()) {
        transport_.updatePeerExtInfo(std::move(ext_info_));
      }
      if (auto info = transport_.peerExtInfo(); info.has_value()) {
        transport_.authState().upstream_ext_info = std::move(info);
      }

      pending_req_.reset();
      transport_.forwardHeader(std::move(msg));
      return absl::OkStatus();
    },
    [&](wire::UserAuthFailureMsg&) {
      return absl::PermissionDeniedError("");
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec