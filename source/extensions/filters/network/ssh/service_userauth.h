#pragma once

#include <tuple>

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/openssh.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

// TODO: configurable?
static constexpr int MaxFailedAuthAttempts = 6; // DEFAULT_AUTH_FAIL_MAX (openssh/servconf.h)
static constexpr int MaxAllowedAuthRequests = 40;

class UserAuthService : public virtual Service,
                        public Logger::Loggable<Logger::Id::filter> {
public:
  std::string name() override { return "ssh-userauth"; };
  UserAuthService(TransportCallbacks& callbacks, Api::Api& api)
      : transport_(callbacks), api_(api) {};

protected:
  TransportCallbacks& transport_;
  Api::Api& api_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;
};

class DownstreamUserAuthService : public UserAuthService,
                                  public StreamMgmtServerMessageHandler {
public:
  DownstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api)
      : UserAuthService(callbacks, api),
        transport_(dynamic_cast<DownstreamTransportCallbacks&>(callbacks)) {}

  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;

  void registerMessageHandlers(StreamMgmtServerMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;

  void startAuthTimer(std::chrono::milliseconds duration) {
    ASSERT(auth_timer_ == nullptr && auth_time_budget_ == 0ms);
    auth_time_budget_ = duration;
    auth_timer_ = transport_.connectionDispatcher()->createTimer([this] {
      onAuthTimeout();
    });
    resumeAuthTimer();
  }

private:
  void onAuthTimeout() {
    auth_timed_out_ = true;
    transport_.terminate(absl::DeadlineExceededError("user auth timed out"));
  }
  void pauseAuthTimer() {
    if (auth_timed_out_) {
      return;
    }
    if (auth_timer_ != nullptr && auth_timer_->enabled()) {
      auth_timer_->disableTimer();
      auto now = transport_.connectionDispatcher()->approximateMonotonicTime();
      auth_time_budget_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::max(0ns, (now - auth_timer_start_)));
      ENVOY_LOG(trace, "auth timer paused (time remaining: {})", auth_time_budget_);
    }
  }
  void resumeAuthTimer() {
    if (auth_timed_out_) {
      return;
    }
    if (auth_timer_ != nullptr && !auth_timer_->enabled()) {
      ENVOY_LOG(trace, "auth timer {} (time remaining: {})",
                (auth_timer_start_.time_since_epoch() == 0ns ? "started" : "resumed"),
                auth_time_budget_);
      auth_timer_start_ = transport_.connectionDispatcher()->approximateMonotonicTime();
      auth_timer_->enableTimer(auth_time_budget_);
    }
  }

  DownstreamTransportCallbacks& transport_;
  std::optional<std::string> pending_service_auth_;
  int auth_request_count_{};
  int auth_failure_count_{};
  bool none_auth_handled_{};
  bool auth_timed_out_{};

  std::chrono::milliseconds auth_time_budget_{};
  MonotonicTime auth_timer_start_;
  Envoy::Event::TimerPtr auth_timer_;
};

// (algorithm, key type, key size in bits)
using key_params_t = std::tuple<std::string, sshkey_types, uint32_t>;

class UpstreamUserAuthService final : public UserAuthService,
                                      public UpstreamService {
public:
  UpstreamUserAuthService(TransportCallbacks& callbacks, Api::Api& api);
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;
  absl::Status requestService() override;
  absl::Status onServiceAccepted() override;

private:
  key_params_t getUpstreamKeyParams();

  openssh::SSHKeySharedPtr user_ca_key_;
  std::unique_ptr<wire::UserAuthRequestMsg> pending_req_;
  bool ext_info_received_{};
};

namespace detail {
std::pair<std::string_view, std::string_view> splitUsername(std::string_view in);
} // namespace detail

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec