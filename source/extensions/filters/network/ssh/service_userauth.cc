#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "bazel-out/k8-dbg/bin/api/extensions/filters/network/ssh/ssh.pb.h"
#include "grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/keys.h"
#include "messages.h"
#include "transport.h"
#include "util.h"
#include <authfile.h>
#include <cstdlib>
#include <sshbuf.h>
#include <sshkey.h>

extern "C" {
#include "openssh/ssh2.h"
#include "openssh/ssherr.h"
}
#define OPTIONS_CRITICAL 1
#define OPTIONS_EXTENSIONS 2
namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  ca_user_key_ = loadSshPrivateKey(transport_.codecConfig().user_ca_key().private_key_file());
  ca_user_pubkey_ = loadSshPublicKey(transport_.codecConfig().user_ca_key().public_key_file());
}

void UserAuthService::registerMessageHandlers(SshMessageDispatcher& dispatcher) const {
  dispatcher.registerHandler(SshMessageType::UserAuthRequest, this);
  dispatcher.registerHandler(SshMessageType::UserAuthSuccess, this);
  dispatcher.registerHandler(SshMessageType::UserAuthFailure, this);
  dispatcher.registerHandler(SshMessageType::UserAuthPubKeyOk, this);
  dispatcher.registerHandler(SshMessageType::UserAuthInfoResponse, this);
}
void DownstreamUserAuthService::registerMessageHandlers(
    StreamMgmtServerMessageDispatcher& dispatcher) const {
  dispatcher.registerHandler(ServerMessage::kAuthResponse, this);
}

absl::Status UserAuthService::requestService() {
  ServiceRequestMsg req;
  req.service_name = name();
  return transport_.sendMessageToConnection(req).status();
}

absl::Status DownstreamUserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type()) {
  case SshMessageType::UserAuthRequest: {
    auto userAuthMsg = msg.unwrap<UserAuthRequestMsg>();

    const std::vector<absl::string_view> parts =
        absl::StrSplit(userAuthMsg.username, absl::MaxSplits("@", 1));
    auto username = parts[0];
    auto hostname = parts[1];
    AuthenticationRequest auth_req;
    auth_req.set_auth_method(userAuthMsg.method_name);
    auth_req.set_hostname(hostname);
    auth_req.set_username(username);

    if (userAuthMsg.method_name == "publickey") {
      auto pubkeyReq = msg.unwrap<PubKeyUserAuthRequestMsg>();

      sshkey* userPubKey;
      sshkey_from_blob(pubkeyReq.public_key.data(), pubkeyReq.public_key.size(), &userPubKey);
      char* fp = sshkey_fingerprint(
          userPubKey, sshkey_type_from_name(pubkeyReq.public_key_alg.c_str()), sshkey_fp_rep(0));
      UserAuthBannerMsg banner{};
      auto msgDump = fmt::format("\r\nmethod:   {}"
                                 "\r\nusername: {}"
                                 "\r\nhostname: {}"
                                 "\r\nkeyalg:   {}"
                                 "\r\npubkey:   {}",
                                 pubkeyReq.method_name, username, hostname,
                                 pubkeyReq.public_key_alg, std::string_view(fp));
      banner.message =
          "\r\n====== TEST BANNER ======" + msgDump + "\r\n=========================\r\n";
      auto _ = transport_.sendMessageToConnection(banner);

      PublicKeyMethodRequest method_req;
      method_req.set_public_key(pubkeyReq.public_key.data(), pubkeyReq.public_key.size());
      method_req.set_public_key_alg(pubkeyReq.public_key_alg);
      auth_req.mutable_method_request()->PackFrom(method_req);

      pomerium::extensions::ssh::ClientMessage clientMsg;
      *clientMsg.mutable_auth_request() = auth_req;
      transport_.sendMgmtClientMessage(clientMsg);

      return absl::OkStatus();
    } else if (userAuthMsg.method_name == "keyboard-interactive") {
      auto interactiveReq = msg.unwrap<KeyboardInteractiveUserAuthRequestMsg>();

      KeyboardInteractiveMethodRequest method_req;
      method_req.mutable_submethods()->Add(interactiveReq.submethods.begin(),
                                           interactiveReq.submethods.end());
      auth_req.mutable_method_request()->PackFrom(method_req);

      pomerium::extensions::ssh::ClientMessage clientMsg;
      *clientMsg.mutable_auth_request() = auth_req;
      transport_.sendMgmtClientMessage(clientMsg);

      return absl::OkStatus();
    } else if (userAuthMsg.method_name == "none") {
      UserAuthFailureMsg failure;
      failure.methods = {"publickey", "keyboard-interactive"};
      return transport_.sendMessageToConnection(failure).status();
    }
    return absl::InvalidArgumentError("unknown or unsupported request"); // TODO
  }
  case SshMessageType::UserAuthInfoResponse: {
    auto infoResp = msg.unwrap<UserInfoResponseMsg>();

    InfoResponse info_resp;
    info_resp.set_method("keyboard-interactive");
    KeyboardInteractiveInfoPromptResponses info_method_resp;
    info_method_resp.mutable_responses()->Add(infoResp.responses.begin(), infoResp.responses.end());
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
      auto list = allow.methods_authenticated();
      state->auth_methods = std::vector<std::string>(list.begin(), list.end());
      auto pubkey = allow.public_key();
      state->public_key.resize(pubkey.size());
      memcpy(state->public_key.data(), pubkey.data(), pubkey.size());
      state->permissions.reset(authResp.release_allow());
      transport_.initUpstream(std::move(state));
      return absl::OkStatus();
    }
    case AuthenticationResponse::kDeny: {
      auto deny = authResp.deny();
      UserAuthFailureMsg failure;
      auto methods = deny.methods();
      failure.methods = std::vector<std::string>(methods.begin(), methods.end());
      return transport_.sendMessageToConnection(failure).status();
    }
    case AuthenticationResponse::kInfoRequest: {
      auto infoReq = authResp.info_request();
      if (infoReq.method() == "keyboard-interactive") {
        KeyboardInteractiveInfoPrompts server_req;
        infoReq.request().UnpackTo(&server_req);

        UserAuthInfoRequestMsg client_req;
        client_req.name = server_req.name();
        client_req.instruction = server_req.instruction();
        client_req.num_prompts = server_req.prompts_size();
        for (const auto& prompt : server_req.prompts()) {
          UserAuthInfoRequestMsg::prompt p;
          p.prompt = prompt.prompt();
          p.echo = prompt.echo();
          client_req.prompts.push_back(std::move(p));
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

absl::Status UpstreamUserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type()) {
  case SshMessageType::ServiceAccept: {
    sshkey* userSessionSshKey;
    if (auto r = sshkey_generate(KEY_ED25519, 256, &userSessionSshKey); r != 0) {
      return absl::InternalError(fmt::format("sshkey_generate failed: {}", ssh_err(r)));
    }

    if (auto r = sshkey_to_certified(userSessionSshKey); r != 0) {
      return absl::InternalError(fmt::format("sshkey_to_certified failed: {}", ssh_err(r)));
    }

    userSessionSshKey->cert->type = SSH2_CERT_TYPE_USER;
    userSessionSshKey->cert->serial = 1;
    userSessionSshKey->cert->nprincipals = 1;
    char** principals = new char*[1];
    principals[0] = const_cast<char*>(strdup(transport_.authState().username.c_str()));
    userSessionSshKey->cert->principals = principals;
    userSessionSshKey->cert->extensions = sshbuf_new();
    for (auto key : {
             // non-critical extensions
             // keep these sorted
             "no-touch-required",
             "permit-X11-forwarding",
             "permit-port-forwarding",
             "permit-pty",
             "permit-user-rc",
         }) {
      sshbuf_put_cstring(userSessionSshKey->cert->extensions, key);
      sshbuf_put_string(userSessionSshKey->cert->extensions, 0, 0);
    }

    time_t now = time(NULL);
    userSessionSshKey->cert->valid_after = ((now - 59) / 60) * 60;
    userSessionSshKey->cert->valid_before = ~0;

    if (auto r = sshkey_from_private(ca_user_key_.get(), &userSessionSshKey->cert->signature_key);
        r != 0) {
      return absl::InternalError(fmt::format("sshkey_from_private failed: {}", ssh_err(r)));
    }

    if (auto r = sshkey_certify(userSessionSshKey, ca_user_key_.get(),
                                sshkey_ssh_name(ca_user_key_.get()), nullptr, nullptr);
        r != 0) {
      return absl::InternalError(fmt::format("sshkey_certify failed: {}", ssh_err(r)));
    }

    auto req = std::make_unique<PubKeyUserAuthRequestMsg>();
    req->username = transport_.authState().username;
    req->method_name = "publickey";
    req->service_name = "ssh-connection";
    req->has_signature = false;
    req->public_key_alg = "ssh-ed25519-cert-v01@openssh.com";
    size_t len = sshbuf_len(userSessionSshKey->cert->certblob);
    req->public_key.resize(len);
    memcpy(req->public_key.data(), sshbuf_ptr(userSessionSshKey->cert->certblob), len);
    pending_req_ = std::move(req);
    pending_user_key_.reset(userSessionSshKey);

    return transport_.sendMessageToConnection(*pending_req_).status();
  }
  case SshMessageType::UserAuthPubKeyOk: {
    if (!pending_req_) {
      return absl::FailedPreconditionError("received unexpected UserAuthPubKeyOk message");
    }
    // compute signature
    Envoy::Buffer::OwnedImpl buf;
    writeString(buf, transport_.getKexResult().SessionID);
    pending_req_->has_signature = true; // see PubKeyUserAuthRequestMsg::writeExtra
    pending_req_->encode(buf);
    auto len = buf.length();
    auto data = static_cast<uint8_t*>(buf.linearize(len));
    uint8_t* sig;
    size_t sig_len;
    auto err = sshkey_sign(pending_user_key_.get(), &sig, &sig_len, data, len, nullptr, nullptr,
                           nullptr, 0);
    if (err != 0) {
      return absl::InternalError(std::string(ssh_err(err)));
    }

    pending_req_->signature.resize(sig_len);
    memcpy(pending_req_->signature.data(), sig, sig_len);

    return transport_.sendMessageToConnection(*pending_req_).status();
  }
  case SshMessageType::UserAuthBanner: {
    auto bannerMsg = msg.unwrap<UserAuthBannerMsg>();
    ENVOY_LOG(info, "banner: \n{}", bannerMsg.message);
    return absl::OkStatus();
  }
  case SshMessageType::UserAuthSuccess: {
    ENVOY_LOG(info, "user auth success: \n{} [{}]", pending_req_->username,
              pending_req_->method_name);

    auto frame = std::make_unique<SSHResponseHeaderFrame>(transport_.authState().stream_id,
                                                          StreamStatus(0, true), std::move(msg));
    transport_.forward(std::move(frame));
    return absl::OkStatus();
  }
  case SshMessageType::UserAuthFailure: {
    auto failureMsg = msg.unwrap<UserAuthFailureMsg>();
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