#include "source/extensions/filters/network/ssh/service_userauth.h"

#include <cstdlib>
#include <memory>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  {
    auto privKey = openssh::SSHKey::fromPrivateKeyFile(transport_.codecConfig().user_ca_key().private_key_file());
    THROW_IF_NOT_OK_REF(privKey.status());
    ca_user_key_ = std::move(*privKey);
  }
  {
    auto pubKey = openssh::SSHKey::fromPublicKeyFile(transport_.codecConfig().user_ca_key().public_key_file());
    THROW_IF_NOT_OK_REF(pubKey.status());
    ca_user_pubkey_ = std::move(*pubKey);
  }
}

void UserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(wire::SshMessageType::UserAuthRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthPubKeyOk, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthInfoResponse, this);
}

void DownstreamUserAuthService::registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) {
  dispatcher.registerHandler(ServerMessage::kAuthResponse, this);
}

absl::Status UserAuthService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(req).status();
}

absl::Status DownstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::UserAuthRequestMsg& msg) {
      const std::vector<absl::string_view> parts =
        absl::StrSplit(*msg.username, absl::MaxSplits('@', 1));
      std::string username, hostname;
      if (parts.size() == 2) {
        username = parts[0];
        hostname = parts[1];
      } else if (parts.size() == 1) {
        username = parts[0];
      }
      if (!stream_id_.has_value()) {
        stream_id_ = api_.randomGenerator().random();
      }
      AuthenticationRequest auth_req;
      auth_req.set_protocol("ssh");
      auth_req.set_service(msg.service_name);
      auth_req.set_auth_method(msg.method_name);
      auth_req.set_hostname(hostname);
      auth_req.set_username(username);

      return msg.msg.visit(
        [&](const wire::PubKeyUserAuthRequestMsg& pubkey_req) {
          auto userPubKey = openssh::SSHKey::fromBlob(pubkey_req.public_key);
          if (!userPubKey.ok()) {
            return userPubKey.status();
          }
          wire::UserAuthBannerMsg banner{};
          auto fingerprint = userPubKey->fingerprint();
          if (!fingerprint.ok()) {
            return fingerprint.status();
          }
          banner.message = fmt::format(
            "\n====== TEST BANNER ======"
            "\nmethod:   {}"
            "\nusername: {}"
            "\nhostname: {}"
            "\nkeyalg:   {}"
            "\npubkey:   {}"
            "\nsession:  {}"
            "\n=========================\n",
            msg.method_name, username, hostname,
            pubkey_req.public_key_alg, *fingerprint, *stream_id_);
          auto _ = transport_.sendMessageToConnection(banner);

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
          return transport_.sendMessageToConnection(failure).status();
        },
        [&](const auto&) {
          ENVOY_LOG(debug, "unsupported user auth request {}", msg.method_name);
          return absl::UnimplementedError("unknown or unsupported auth method");
        });
    },
    [&](Envoy::OptRef<wire::UserAuthInfoResponseMsg> msg) {
      if (!msg.has_value()) {
        return absl::InvalidArgumentError("unexpected UserAuthInfoResponseMsg received");
      }
      InfoResponse info_resp;
      info_resp.set_method("keyboard-interactive");
      KeyboardInteractiveInfoPromptResponses info_method_resp;
      for (const auto& resp : *msg->responses) {
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
      ASSERT(stream_id_.has_value());
      state->stream_id = *stream_id_;
      switch (allow.target_case()) {
      case pomerium::extensions::ssh::AllowResponse::kUpstream:
        state->channel_mode = ChannelMode::Normal;
        state->multiplexing_info = MultiplexingInfo{};
        state->multiplexing_info.multiplex_mode = MultiplexMode::Source;
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
      wire::UserAuthFailureMsg failure;
      auto methods = deny.methods();
      failure.methods = string_list(methods.begin(), methods.end());
      return transport_.sendMessageToConnection(failure).status();
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
        return transport_.sendMessageToConnection(client_req).status();
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

absl::Status UpstreamUserAuthService::handleMessage(wire::Message&& msg) {
  return msg.visit(
    [&](wire::ServiceAcceptMsg&) {
      if (!transport_.authState().allow_response) {
        return absl::InternalError("missing AllowResponse in auth state");
      }
      auto userSessionSshKey = openssh::SSHKey::generate(KEY_ED25519, 256);
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
        ca_user_key_);
      if (!stat.ok()) {
        return stat;
      }

      auto req = std::make_unique<wire::UserAuthRequestMsg>();
      req->username = transport_.authState().allow_response->username();
      req->method_name = "publickey";
      req->service_name = "ssh-connection";

      wire::PubKeyUserAuthRequestMsg pubkeyReq;
      pubkeyReq.has_signature = false;
      pubkeyReq.public_key_alg = "ssh-ed25519-cert-v01@openssh.com";

      auto blob = userSessionSshKey->toBlob();
      if (!blob.ok()) {
        return blob.status();
      }
      pubkeyReq.public_key = *blob;
      req->msg = std::move(pubkeyReq);
      pending_req_ = std::move(req);
      pending_user_key_ = std::move(*userSessionSshKey);

      return transport_.sendMessageToConnection(*pending_req_).status();
    },
    [&](Envoy::OptRef<wire::UserAuthPubKeyOkMsg> opt_msg) {
      if (!opt_msg.has_value() || !pending_req_) {
        return absl::FailedPreconditionError("received unexpected UserAuthPubKeyOk message");
      }
      // compute signature
      Envoy::Buffer::OwnedImpl buf;
      wire::write_opt<wire::LengthPrefixed>(buf, transport_.getKexResult().session_id);
      pending_req_->msg.get<wire::PubKeyUserAuthRequestMsg>().has_signature = true; // see PubKeyUserAuthRequestMsg::writeExtra
      auto stat = pending_req_->encode(buf);
      if (!stat.ok()) {
        return stat.status();
      }
      auto sig = pending_user_key_.sign(wire::flushTo<bytes>(buf));
      if (!sig.ok()) {
        return sig.status();
      }
      pending_req_->msg.get<wire::PubKeyUserAuthRequestMsg>().signature = *sig;
      return transport_.sendMessageToConnection(*pending_req_).status();
    },
    [](wire::UserAuthBannerMsg& msg) {
      ENVOY_LOG(info, "banner: \n{}", msg.message);
      return absl::OkStatus();
    },
    [&](wire::UserAuthSuccessMsg& msg) {
      ENVOY_LOG(info, "user auth success: \n{} [{}]", pending_req_->username,
                pending_req_->method_name);

      transport_.forward(std::make_unique<SSHResponseHeaderFrame>(
        transport_.authState().stream_id, StreamStatus(0, true), std::move(msg)));
      return absl::OkStatus();
    },
    [&](wire::UserAuthFailureMsg& msg) {
      if (msg.partial) {
        return transport_.sendMessageToConnection(msg).status();
      }
      return absl::UnauthenticatedError(fmt::format("auth failure: {}", msg.methods));
    },
    [](auto&) {
      ENVOY_LOG(error, "unknown message");
      return absl::OkStatus();
    });
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec