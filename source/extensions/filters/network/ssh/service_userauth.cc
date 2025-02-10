#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/keys.h"
#include "messages.h"
#include <authfile.h>
#include <sshbuf.h>
#include <sshkey.h>

extern "C" {
#include "openssh/ssh2.h"
}
namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

UserAuthService::UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
    : transport_(callbacks), api_(api) {
  ca_user_key_ = loadSshPrivateKey("source/extensions/filters/network/ssh/testdata/ca_user_key");
  (void)api_;
}

absl::Status UserAuthService::handleMessage(AnyMsg&& msg) {
  switch (msg.msg_type) {
  case SshMessageType::UserAuthRequest: { // server
    auto userAuthMsg = msg.unwrap<UserAuthRequestMsg>();

    UserAuthBannerMsg banner{};
    banner.message = "\r\n====== TEST BANNER ======" +
                     fmt::format("\r\n====== sign in as: {} ======\r\n", userAuthMsg.username);
    auto _ = transport_.sendMessageToConnection(banner);

    // test code
    const std::vector<absl::string_view> parts =
        absl::StrSplit(userAuthMsg.username, absl::MaxSplits("@", 1));
    auto username = parts[0];
    auto hostname = parts[1];
    transport_.initUpstream(username, hostname);

    return absl::OkStatus();
    // return callbacks_.downstream().sendMessage(EmptyMsg<SshMessageType::UserAuthSuccess>());
  }
  case SshMessageType::ServiceAccept: { // client
    auto pub = loadSshPublicKey("source/extensions/filters/network/ssh/testdata/ca_user_key.pub");

    if (sshkey_to_certified(pub.get()) != 0) {
      return absl::InternalError("sshkey_to_certified failed");
    }
    pub->cert->type = SSH2_CERT_TYPE_USER;
    sshkey_from_private(ca_user_key_.get(), &pub->cert->signature_key);
    sshkey_certify(pub.get(), ca_user_key_.get(), sshkey_type(ca_user_key_.get()), nullptr,
                   nullptr);

    auto req = std::make_unique<PubKeyUserAuthRequestMsg>();
    req->username = username_;
    req->method_name = "publickey";
    req->service_name = "ssh-connection";
    req->has_signature = false;
    req->public_key_alg = "ssh-ed25519";
    char* out;
    size_t len;
    sshbuf_get_cstring(pub->cert->certblob, &out, &len);
    req->public_key.resize(len);
    memcpy(req->public_key.data(), out, len);
    pending_req_ = std::move(req);

    // req.public_key = transport_.getKexResult().HostKeyBlob;
    return transport_.sendMessageToConnection(*pending_req_).status();
  }
  case SshMessageType::UserAuthBanner: {
    auto bannerMsg = msg.unwrap<UserAuthBannerMsg>();
    ENVOY_LOG(info, "banner: \n{}", bannerMsg.message);
    break;
  }
  case SshMessageType::UserAuthSuccess: { // client

    break;
  }
  case SshMessageType::UserAuthFailure: { // client
    auto failureMsg = msg.unwrap<UserAuthFailureMsg>();
    return absl::UnauthenticatedError(fmt::format("auth failure: {}", failureMsg.methods));
  }
  case SshMessageType::UserAuthPubKeyOk: { // client
    if (pending_req_) {
      pending_req_->has_signature = true;
      // compute signature
      Envoy::Buffer::OwnedImpl buf;
      writeBytes(buf, transport_.getKexResult().SessionID);
      pending_req_->encode(buf);

      if (auto sig = transport_.signWithHostKey(buf); !sig.ok()) {
        return sig.status();
      } else {
        pending_req_->signature = std::move(sig.value());
      }
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