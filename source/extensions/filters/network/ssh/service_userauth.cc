#include "source/extensions/filters/network/ssh/service_userauth.h"

#include <cstdlib>

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/wire/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  {
    auto privKey = openssh::SSHKey::fromPrivateKeyFile(transport_.codecConfig().user_ca_key().private_key_file());
    THROW_IF_NOT_OK(privKey.status());
    ca_user_key_ = std::move(*privKey);
  }
  {
    auto pubKey = openssh::SSHKey::fromPublicKeyFile(transport_.codecConfig().user_ca_key().public_key_file());
    THROW_IF_NOT_OK(pubKey.status());
    ca_user_pubkey_ = std::move(*pubKey);
  }
}

void UserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
  dispatcher.registerHandler(wire::SshMessageType::UserAuthRequest, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthSuccess, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthFailure, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthPubKeyOk, this);
  dispatcher.registerHandler(wire::SshMessageType::UserAuthInfoResponse, this);
}
void DownstreamUserAuthService::registerMessageHandlers(
    StreamMgmtServerMessageDispatcher& dispatcher) const {
  dispatcher.registerHandler(ServerMessage::kAuthResponse, this);
}

absl::Status UserAuthService::requestService() {
  wire::ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(req).status();
}

absl::Status DownstreamUserAuthService::handleMessage(wire::SshMsg&& msg) {
  switch (msg.msg_type()) {
  case wire::SshMessageType::UserAuthRequest: {
    const auto& userAuthMsg = dynamic_cast<const wire::UserAuthRequestMsg&>(msg);

    const std::vector<absl::string_view> parts =
        absl::StrSplit(*userAuthMsg.username, absl::MaxSplits("@", 1));
    std::string username, hostname;
    if (parts.size() == 2) {
      username = parts[0];
      hostname = parts[1];
    }
    AuthenticationRequest auth_req;
    auth_req.set_protocol("ssh");
    auth_req.set_service(userAuthMsg.service_name);
    auth_req.set_auth_method(userAuthMsg.method_name);
    auth_req.set_hostname(hostname);
    auth_req.set_username(username);

    return userAuthMsg.msg.visit(
        [&](const wire::PubKeyUserAuthRequestMsg& pubkeyReq) {
          auto userPubKey = openssh::SSHKey::fromBlob(pubkeyReq.public_key);
          wire::UserAuthBannerMsg banner{};
          auto msgDump = fmt::format("\r\nmethod:   {}"
                                     "\r\nusername: {}"
                                     "\r\nhostname: {}"
                                     "\r\nkeyalg:   {}"
                                     "\r\npubkey:   {}",
                                     userAuthMsg.method_name, username, hostname,
                                     pubkeyReq.public_key_alg, userPubKey->fingerprint());
          banner.message =
              "\r\n====== TEST BANNER ======" + msgDump + "\r\n=========================\r\n";
          auto _ = transport_.sendMessageToConnection(banner);

          PublicKeyMethodRequest method_req;
          method_req.set_public_key(pubkeyReq.public_key->data(), pubkeyReq.public_key->size());
          method_req.set_public_key_alg(pubkeyReq.public_key_alg);
          auth_req.mutable_method_request()->PackFrom(method_req);

          pomerium::extensions::ssh::ClientMessage clientMsg;
          *clientMsg.mutable_auth_request() = auth_req;
          transport_.sendMgmtClientMessage(clientMsg);

          return absl::OkStatus();
        },
        [&](const wire::KeyboardInteractiveUserAuthRequestMsg& interactiveReq) {
          KeyboardInteractiveMethodRequest method_req;
          for (const auto& sm : *interactiveReq.submethods) {
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
          failure.methods = {"publickey"s, "keyboard-interactive"s};
          return transport_.sendMessageToConnection(failure).status();
        },
        [&](std::monostate) {
          ENVOY_LOG(debug, "unsupported user auth request {}", userAuthMsg.method_name);
          return absl::UnimplementedError("unknown or unsupported auth method");
        });
  }
  case wire::SshMessageType::UserAuthInfoResponse: {
    const auto& infoResp = dynamic_cast<const wire::UserAuthInfoResponseMsg&>(msg);

    InfoResponse info_resp;
    info_resp.set_method("keyboard-interactive");
    KeyboardInteractiveInfoPromptResponses info_method_resp;
    for (const auto& resp : *infoResp.responses) {
      info_method_resp.add_responses(resp);
    }
    info_resp.mutable_response()->PackFrom(info_method_resp);

    pomerium::extensions::ssh::ClientMessage clientMsg;
    *clientMsg.mutable_info_response() = info_resp;
    transport_.sendMgmtClientMessage(clientMsg);

    return absl::OkStatus();
  }
  default:
    PANIC("unimplemented");
  }
}

absl::Status DownstreamUserAuthService::handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) {
  switch (message->message_case()) {
  case pomerium::extensions::ssh::ServerMessage::kAuthResponse: {
    auto authResp = message->auth_response();
    switch (authResp.response_case()) {
    case AuthenticationResponse::kAllow: {
      auto allow = authResp.allow();
      auto state = std::make_shared<AuthState>();
      state->hostname = allow.hostname();
      state->username = allow.username();
      state->stream_id = api_.randomGenerator().random();
      switch (allow.target()) {
      case pomerium::extensions::ssh::Upstream:
        state->channel_mode = ChannelMode::Normal;
        break;
      case pomerium::extensions::ssh::Internal:
        state->channel_mode = ChannelMode::Hijacked;
        break;
      default:
        return absl::InternalError("invalid target");
      }

      for (const auto& am : allow.allowed_methods()) {
        state->auth_methods.push_back(am.method());
        if (am.method() == "publickey") {
          PublicKeyAllowResponse pubkey;
          am.method_data().UnpackTo(&pubkey);
          state->public_key.resize(pubkey.public_key().size());
          memcpy(state->public_key.data(), pubkey.public_key().data(), pubkey.public_key().size());
          state->permissions.reset(pubkey.release_permissions());
        }
      }
      transport_.initUpstream(std::move(state));
      return absl::OkStatus();
    }
    case AuthenticationResponse::kDeny: {
      auto deny = authResp.deny();
      wire::UserAuthFailureMsg failure;
      auto methods = deny.methods();
      failure.methods = string_list(methods.begin(), methods.end());
      return transport_.sendMessageToConnection(failure).status();
    }
    case AuthenticationResponse::kInfoRequest: {
      auto infoReq = authResp.info_request();
      if (infoReq.method() == "keyboard-interactive") {
        KeyboardInteractiveInfoPrompts server_req;
        infoReq.request().UnpackTo(&server_req);

        wire::UserAuthInfoRequestMsg client_req;
        client_req.name = server_req.name();
        client_req.instruction = server_req.instruction();
        for (const auto& prompt : server_req.prompts()) {
          wire::userAuthInfoPrompt p;
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

absl::Status UpstreamUserAuthService::handleMessage(wire::SshMsg&& msg) {
  switch (msg.msg_type()) {
  case wire::SshMessageType::ServiceAccept: {
    auto userSessionSshKey = openssh::SSHKey::generate(KEY_ED25519, 256);
    auto stat = userSessionSshKey->convertToSignedUserCertificate(
        1,
        {transport_.authState().username},
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
    req->username = transport_.authState().username;
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
  }
  case wire::SshMessageType::UserAuthPubKeyOk: {
    if (!pending_req_) {
      return absl::FailedPreconditionError("received unexpected UserAuthPubKeyOk message");
    }
    const auto& pubkeyOkMsg = dynamic_cast<const wire::UserAuthPubKeyOkMsg&>(msg);
    (void)pubkeyOkMsg;
    // compute signature
    Envoy::Buffer::OwnedImpl buf;
    wire::write_opt<wire::LengthPrefixed>(buf, transport_.getKexResult().SessionID);
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
  }
  case wire::SshMessageType::UserAuthBanner: {
    const auto& bannerMsg = dynamic_cast<const wire::UserAuthBannerMsg&>(msg);
    ENVOY_LOG(info, "banner: \n{}", bannerMsg.message);
    return absl::OkStatus();
  }
  case wire::SshMessageType::UserAuthSuccess: {
    ENVOY_LOG(info, "user auth success: \n{} [{}]", pending_req_->username,
              pending_req_->method_name);

    auto frame = std::make_unique<SSHResponseHeaderFrame>(
        transport_.authState().stream_id,
        StreamStatus(0, true),
        dynamic_cast<wire::UserAuthSuccessMsg&&>(msg));
    transport_.forward(std::move(frame));
    return absl::OkStatus();
  }
  case wire::SshMessageType::UserAuthFailure: {
    const auto& failureMsg = dynamic_cast<const wire::UserAuthFailureMsg&>(msg);
    if (failureMsg.partial) {
      return transport_.sendMessageToConnection(failureMsg).status();
    }
    return absl::UnauthenticatedError(fmt::format("auth failure: {}", failureMsg.methods));
  }
  default:
    PANIC("unimplemented");
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec