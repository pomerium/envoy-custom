#include "source/extensions/filters/network/ssh/service_userauth.h"
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

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  ca_user_key_ = loadSshPrivateKey("source/extensions/filters/network/ssh/testdata/ca_user_key");
  (void)api_;
}

absl::Status UserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msgtype) {
  case SshMessageType::UserAuthRequest: { // server
    auto userAuthMsg = msg.unwrap<UserAuthRequestMsg>();

    if (userAuthMsg.method_name == "publickey") {
      auto pubkeyReq = msg.unwrap<PubKeyUserAuthRequestMsg>();

      // test code
      const std::vector<absl::string_view> parts =
          absl::StrSplit(userAuthMsg.username, absl::MaxSplits("@", 1));
      auto username = parts[0];
      auto hostname = parts[1];

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

      auto state = std::make_unique<downstream_state_t>();
      state->hostname = hostname;
      state->username = username;
      state->pubkey = std::make_unique<PubKeyUserAuthRequestMsg>();
      state->stream_id = api_.randomGenerator().random();
      *state->pubkey = pubkeyReq;
      transport_.initUpstream(std::move(state));

      return absl::OkStatus();
    } else {
      UserAuthFailureMsg failure;
      failure.methods = {"publickey"};
      return transport_.sendMessageToConnection(failure).status();
    }
    break;
  }

  case SshMessageType::ServiceAccept: { // client
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
    principals[0] = const_cast<char*>(strdup(transport_.getDownstreamState().username.c_str()));
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
    req->username = transport_.getDownstreamState().username;
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
  case SshMessageType::UserAuthBanner: {
    auto bannerMsg = msg.unwrap<UserAuthBannerMsg>();
    ENVOY_LOG(info, "banner: \n{}", bannerMsg.message);
    break;
  }
  case SshMessageType::UserAuthSuccess: { // client
    ENVOY_LOG(info, "user auth success: \n{} [{}]", pending_req_->username,
              pending_req_->method_name);

    auto frame = std::make_unique<SSHResponseHeaderFrame>(transport_.getDownstreamState().stream_id,
                                                          StreamStatus(0, true), std::move(msg));
    transport_.forward(std::move(frame));
    return absl::OkStatus();
  }
  case SshMessageType::UserAuthFailure: { // client
    auto failureMsg = msg.unwrap<UserAuthFailureMsg>();
    return absl::UnauthenticatedError(fmt::format("auth failure: {}", failureMsg.methods));
  }
  case SshMessageType::UserAuthPubKeyOk: { // client
    if (pending_req_) {
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
  }
  default:
    // specific protocols
    break;
  }
  return absl::OkStatus();
}

void UserAuthService::registerMessageHandlers(MessageDispatcher& dispatcher) {
  dispatcher.registerHandler(SshMessageType::UserAuthRequest, this);
  dispatcher.registerHandler(SshMessageType::UserAuthSuccess, this);
  dispatcher.registerHandler(SshMessageType::UserAuthFailure, this);
  dispatcher.registerHandler(SshMessageType::UserAuthPubKeyOk, this);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec