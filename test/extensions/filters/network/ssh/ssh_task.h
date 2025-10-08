#pragma once

#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

#define OR_FAIL                                                           \
  [&](const auto& msg) {                                                  \
    ADD_FAILURE() << fmt::format("received unexpected message: {}", msg); \
  }

inline std::chrono::milliseconds defaultTimeout() {
  CONSTRUCT_ON_FIRST_USE(std::chrono::milliseconds,
                         isDebuggerAttached()
                           ? std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours(1))
                           : std::chrono::milliseconds(10000));
}

class Task : public SshMessageMiddleware {
  friend class SshConnectionDriver;

public:
  Task() = default;
  virtual ~Task() = default;
  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;

protected:
  virtual void start() PURE;
  virtual void onMessageReceived(wire::Message& msg) PURE;

  // Can be overridden to provide more details/current state on failure
  virtual absl::Status errorDetails() {
    return absl::InternalError("task failed via assertion");
  }

  void taskSuccess() {
    ASSERT(!task_success_called_ && !task_failure_called_);
    task_success_called_ = true;
    callbacks_->taskSuccess();
  }

  void taskFailure(absl::Status err) {
    ASSERT(!task_success_called_ && !task_failure_called_);
    task_failure_called_ = true;
    callbacks_->taskFailure(err);
  }

  class TaskCallbacks {
  public:
    virtual ~TaskCallbacks() = default;
    virtual void sendMessage(wire::Message&&) PURE;
    virtual KexResult& kexResult() PURE;
    virtual openssh::SSHKey& clientKey() PURE;
    virtual void waitForManagementRequest(Protobuf::Message& req) PURE;
    virtual void sendManagementResponse(const Protobuf::Message& resp) PURE;
    virtual void setTimeout(std::chrono::milliseconds timeout) PURE;

  private:
    friend void Task::taskSuccess();
    friend void Task::taskFailure(absl::Status err);
    virtual void taskSuccess() PURE;
    virtual void taskFailure(absl::Status err) PURE;
  };

  TaskCallbacks* callbacks_;
  stream_id_t stream_id_;

private:
  void setTaskCallbacks(TaskCallbacks& cb, stream_id_t stream_id) {
    callbacks_ = &cb;
    stream_id_ = stream_id;
  }
  void startInternal() {
    start();
    if (testing::Test::HasFailure()) {
      taskFailure(errorDetails());
    }
  }
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) final {
    // FIXME: this needs a way to filter channel messages intended for other middlewares
    onMessageReceived(msg);
    if (testing::Test::HasFailure()) {
      taskFailure(errorDetails());
    }
    return MiddlewareResult::Break |
           ((task_failure_called_ || task_success_called_)
              ? MiddlewareResult::UninstallSelf
              : MiddlewareResult(0));
  }

  bool task_success_called_{};
  bool task_failure_called_{};
};

using TaskPtr = std::unique_ptr<Task>;

namespace Tasks {

class RequestUserAuthService : public Task {
public:
  void start() override {
    callbacks_->sendMessage(wire::ServiceRequestMsg{
      .service_name = "ssh-userauth"s,
    });
  }

  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ServiceAcceptMsg&) {
        taskSuccess();
      },
      OR_FAIL);
  }
};

class Authenticate : public Task {
public:
  Authenticate(std::string username = "user", bool internal = true)
      : username_(username),
        internal_(internal) {}
  void start() override {
    wire::UserAuthRequestMsg req;
    req.username = username_;
    req.service_name = "ssh-connection";

    auto& key = callbacks_->clientKey();
    wire::PubKeyUserAuthRequestMsg pubkeyReq{
      .has_signature = true,
      .public_key_alg = key.signatureAlgorithmsForKeyType()[0],
      .public_key = key.toPublicKeyBlob(),
    };
    // compute signature
    Envoy::Buffer::OwnedImpl buf;
    wire::write_opt<wire::LengthPrefixed>(buf, callbacks_->kexResult().session_id);
    constexpr static wire::field<std::string, wire::LengthPrefixed> method_name =
      std::string(wire::PubKeyUserAuthRequestMsg::submsg_key);
    ASSERT_OK(wire::encodeMsg(buf, req.type,
                              req.username,
                              req.service_name,
                              method_name,
                              pubkeyReq.has_signature,
                              pubkeyReq.public_key_alg,
                              pubkeyReq.public_key));
    auto sig = key.sign(wire::flushTo<bytes>(buf), pubkeyReq.public_key_alg);
    ASSERT_OK(sig);
    pubkeyReq.signature = *sig;
    req.request = std::move(pubkeyReq);
    callbacks_->sendMessage(std::move(req));

    ClientMessage clientMsg;
    callbacks_->waitForManagementRequest(clientMsg);
    ASSERT_EQ("publickey", clientMsg.auth_request().auth_method());
    pomerium::extensions::ssh::FilterMetadata filterMetadata;
    filterMetadata.set_stream_id(stream_id_);
    // Only the stream id is set here, not channel id.
    // TODO: maybe refactor this api to be less confusing

    if (internal_) {
      ServerMessage serverMsg;
      (*serverMsg.mutable_auth_response()
          ->mutable_allow()
          ->mutable_internal()
          ->mutable_set_metadata()
          ->mutable_typed_filter_metadata())["com.pomerium.ssh"]
        .PackFrom(filterMetadata);
      callbacks_->sendManagementResponse(serverMsg);
    } else {
      PANIC("unimplemented");
    }
  };

  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::UserAuthSuccessMsg&) {
        taskSuccess();
      },
      [&](const wire::UserAuthFailureMsg& msg) {
        taskFailure(absl::InternalError(fmt::format("received auth failure: {}", msg)));
      },
      [&](const wire::UserAuthBannerMsg&) {
        // ignore for now
      },
      OR_FAIL);
  };

  const std::string username_;
  const bool internal_{};
};

class RequestReversePortForward : public Task {
public:
  RequestReversePortForward(const std::string& address, uint32_t port, uint32_t server_port)
      : address_(address),
        port_(port),
        server_port_(server_port) {}
  void start() override {
    callbacks_->sendMessage(wire::GlobalRequestMsg{
      .want_reply = true,
      .request = wire::TcpipForwardMsg{
        .remote_address = address_,
        .remote_port = port_,
      },
    });
    ClientMessage clientMsg;
    callbacks_->waitForManagementRequest(clientMsg);
    ASSERT_EQ(address_, clientMsg.global_request().tcpip_forward_request().remote_address());
    ASSERT_EQ(port_, clientMsg.global_request().tcpip_forward_request().remote_port());
    ServerMessage serverMsg;
    serverMsg.mutable_global_request_response()
      ->set_success(true);
    serverMsg.mutable_global_request_response()
      ->mutable_tcpip_forward_response()
      ->set_server_port(server_port_);
    callbacks_->sendManagementResponse(serverMsg);
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](wire::GlobalRequestSuccessMsg& msg) {
        ASSERT_OK(msg.resolve<wire::TcpipForwardResponseMsg>());
        ASSERT_EQ(server_port_, *msg.response.get<wire::TcpipForwardResponseMsg>().server_port);
        taskSuccess();
      },
      [&](const wire::GlobalRequestFailureMsg& msg) {
        taskFailure(absl::InternalError(fmt::format("request failed: {}", msg)));
      },
      OR_FAIL);
  };

  const std::string address_;
  const uint32_t port_;
  const uint32_t server_port_;
};

class AcceptReversePortForward : public Task {
public:
  AcceptReversePortForward(const std::string& address_connected, uint32_t port_connected,
                           uint32_t local_channel_id, uint32_t* remote_channel_id)
      : address_connected_(address_connected),
        port_connected_(port_connected),
        local_channel_id_(local_channel_id),
        remote_channel_id_(remote_channel_id) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelOpenMsg& open_msg) {
        ASSERT_EQ(wire::ChannelWindowSize, open_msg.initial_window_size);
        ASSERT_EQ(131072, *open_msg.max_packet_size);
        *remote_channel_id_ = open_msg.sender_channel;
        open_msg.request.visit(
          [&](const wire::ForwardedTcpipChannelOpenMsg& msg) {
            ASSERT_EQ(address_connected_, msg.address_connected);
            ASSERT_EQ(port_connected_, msg.port_connected);
            ASSERT_THAT(*msg.originator_address, AnyOf(Eq("127.0.0.1"s), Eq("::1"s)));
            ASSERT_NE(0, *msg.originator_port);
            callbacks_->sendMessage(wire::ChannelOpenConfirmationMsg{
              .recipient_channel = open_msg.sender_channel,
              .sender_channel = local_channel_id_,
              .initial_window_size = wire::ChannelWindowSize,
              .max_packet_size = 131072,
            });
            taskSuccess();
          },
          OR_FAIL);
      },
      OR_FAIL);
  }

  const std::string address_connected_;
  const uint32_t port_connected_;
  const uint32_t local_channel_id_;
  uint32_t* const remote_channel_id_;
};

class WaitForChannelData : public Task {
public:
  WaitForChannelData(uint32_t channel_id, const std::string& expected_data)
      : channel_id_(channel_id),
        expected_data_(expected_data) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        auto view = std::string_view(reinterpret_cast<const char*>(msg.data->data()), msg.data->size());
        if (view.size() >= expected_data_.size()) {
          ASSERT_THAT(view, testing::StartsWith(expected_data_));
          expected_data_.clear();
          taskSuccess();
        } else {
          expected_data_ = absl::StripPrefix(expected_data_, view);
        }
      },
      [&](const auto&) {});
  }
  absl::Status errorDetails() override {
    return absl::InternalError(fmt::format("expected bytes not received: '{}'", absl::CHexEscape(expected_data_)));
  }
  const uint32_t channel_id_;
  std::string expected_data_;
};

class WaitForChannelCloseByPeer : public Task {
public:
  WaitForChannelCloseByPeer(uint32_t channel_id, uint32_t remote_channel_id, bool allow_eof = true)
      : channel_id_(channel_id),
        remote_channel_id_(remote_channel_id),
        allow_eof_(allow_eof) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelCloseMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        callbacks_->sendMessage(wire::ChannelCloseMsg{
          .recipient_channel = remote_channel_id_,
        });
        taskSuccess();
      },
      [&](const wire::ChannelEOFMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        ASSERT_TRUE(allow_eof_);
      },
      OR_FAIL);
  }
  const uint32_t channel_id_;
  const uint32_t remote_channel_id_;
  const bool allow_eof_;
};

class SendChannelCloseAndWait : public Task {
public:
  SendChannelCloseAndWait(uint32_t channel_id, uint32_t remote_channel_id, bool allow_eof = true)
      : channel_id_(channel_id),
        remote_channel_id_(remote_channel_id),
        allow_eof_(allow_eof) {}
  void start() override {
    callbacks_->sendMessage(wire::ChannelCloseMsg{
      .recipient_channel = remote_channel_id_,
    });
    callbacks_->setTimeout(defaultTimeout());
  }
  void onMessageReceived(wire::Message& msg) override {
    msg.visit(
      [&](const wire::ChannelCloseMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        taskSuccess();
      },
      [&](const wire::ChannelEOFMsg& msg) {
        ASSERT_EQ(channel_id_, *msg.recipient_channel);
        ASSERT_TRUE(allow_eof_);
      },
      OR_FAIL);
  }
  const uint32_t channel_id_;
  const uint32_t remote_channel_id_;
  const bool allow_eof_;
};

} // namespace Tasks

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec