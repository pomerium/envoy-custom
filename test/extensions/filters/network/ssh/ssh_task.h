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
#include <any>
#include <memory>
#include <type_traits>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

#define OR_FAIL                                                           \
  [&](const auto& msg) {                                                  \
    ADD_FAILURE() << fmt::format("received unexpected message: {}", msg); \
  }

#define DEFAULT_NOOP \
  [&](const auto&) {}

#define DEFAULT_BREAK \
  [&](const auto&) { return MiddlewareResult::Break; }

#define DEFAULT_CONTINUE \
  [&](const auto&) { return MiddlewareResult::Continue; }

inline std::chrono::milliseconds defaultTimeout() {
  CONSTRUCT_ON_FIRST_USE(std::chrono::milliseconds,
                         isDebuggerAttached()
                           ? std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours(1))
                           : std::chrono::milliseconds(10000));
}

class TaskCallbacks {
  template <typename, typename>
  friend class Task;
  template <typename>
  friend class TaskSuccess;
  friend class UntypedTask;

public:
  virtual ~TaskCallbacks() = default;
  virtual void sendMessage(wire::Message&&) PURE;
  virtual KexResult& kexResult() PURE;
  virtual openssh::SSHKey& clientKey() PURE;
  virtual void waitForManagementRequest(Protobuf::Message& req) PURE;
  virtual void sendManagementResponse(const Protobuf::Message& resp) PURE;
  virtual void setTimeout(std::chrono::milliseconds timeout) PURE;

private:
  virtual void taskSuccess(std::any output, std::function<void(const std::any&, void*)> apply_fn) PURE;
  virtual void taskFailure(absl::Status err) PURE;
};

class UntypedTaskCallbacksHandle {
public:
  virtual ~UntypedTaskCallbacksHandle() = default;
  virtual UntypedTaskCallbacksHandle& start(std::any input) PURE;
  virtual UntypedTaskCallbacksHandle& saveOutput(void* output) PURE;
  virtual UntypedTaskCallbacksHandle& then(UntypedTaskCallbacksHandle& next) PURE;
};

template <typename Input, typename Output>
class TaskCallbacksHandle {
public:
  using input_type = Input;
  using output_type = Output;

  TaskCallbacksHandle(UntypedTaskCallbacksHandle& untyped)
      : untyped_(untyped) {}
  virtual ~TaskCallbacksHandle() = default;

  TaskCallbacksHandle(const TaskCallbacksHandle&) = default;
  TaskCallbacksHandle(TaskCallbacksHandle&&) = default;
  TaskCallbacksHandle& operator=(const TaskCallbacksHandle&) = default;
  TaskCallbacksHandle& operator=(TaskCallbacksHandle&&) = default;

  template <typename I>
    requires (std::is_same_v<I, Input> && !std::is_void_v<I>)
  TaskCallbacksHandle<Input, Output> start(I input) {
    auto& handle = untyped_.start(std::any(input));
    return {handle};
  }

  template <typename I = Input>
    requires (std::is_same_v<I, Input> && std::is_void_v<I>)
  TaskCallbacksHandle<Input, Output> start() {
    auto& handle = untyped_.start({});
    return {handle};
  }

  TaskCallbacksHandle<Input, Output> saveOutput(Output* output)
    requires (!std::is_void_v<Output>)
  {
    auto& handle = untyped_.saveOutput(output);
    return {handle};
  }

  template <typename NextInput, typename NextOutput>
    requires (std::is_same_v<NextInput, Output> || std::is_void_v<NextInput>)
  TaskCallbacksHandle<Input, Output> then(TaskCallbacksHandle<NextInput, NextOutput> next) {
    auto& handle = untyped_.then(next.untyped_);
    return {handle};
  }

  operator UntypedTaskCallbacksHandle&() { return untyped_; }

  UntypedTaskCallbacksHandle& untyped_;
};

class UntypedTask : public SshMessageMiddleware {
  friend class SshConnectionDriver;
  template <typename, typename>
  friend class Task;

public:
  UntypedTask() = default;
  virtual ~UntypedTask() = default;
  UntypedTask(const UntypedTask&) = delete;
  UntypedTask& operator=(const UntypedTask&) = delete;

protected:
  virtual void startUntyped(std::any input) PURE;
  virtual MiddlewareResult onMessageReceived(wire::Message& msg) PURE;

  // Can be overridden to provide more details/current state on failure
  virtual absl::Status errorDetails() {
    return absl::InternalError("task failed via assertion");
  }

  void taskFailure(absl::Status err) {
    ASSERT(!task_success_called_ && !task_failure_called_);
    task_failure_called_ = true;
    callbacks_->taskFailure(err);
  }

  TaskCallbacks* callbacks_;
  stream_id_t stream_id_;

  bool task_success_called_{};
  bool task_failure_called_{};

private:
  void setTaskCallbacks(TaskCallbacks& cb, stream_id_t stream_id) {
    callbacks_ = &cb;
    stream_id_ = stream_id;
  }
  void startInternalUntyped(std::any input) {
    startUntyped(std::move(input));
    if (testing::Test::HasFailure()) {
      taskFailure(errorDetails());
    }
  }
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) final {
    auto res = onMessageReceived(msg);
    ASSERT((res & MiddlewareResult::UninstallSelf) == 0,
           "Do not return MiddlewareResult::UninstallSelf from Task::interceptMessage; "
           "call taskSuccess() or taskFailure() instead.");
    if (testing::Test::HasFailure()) {
      taskFailure(errorDetails());
    }
    if (task_success_called_ || task_failure_called_) {
      res |= MiddlewareResult::UninstallSelf;
    }
    return res;
  }
};

template <typename Input>
class TaskStart : public virtual UntypedTask {
public:
  virtual ~TaskStart() = default;
  virtual void start(Input input) PURE;

protected:
  void startUntyped(std::any input) final {
    start(std::any_cast<Input>(input));
  }
};

template <>
class TaskStart<void> : public virtual UntypedTask {
public:
  virtual ~TaskStart() = default;
  virtual void start() PURE;

protected:
  void startUntyped(std::any) final {
    // the input may still have a value, but it should be ignored; this task accepts no input
    start();
  }
};

namespace {
template <typename Output>
constexpr void apply_output(const std::any& value, void* output) {
  *static_cast<Output*>(output) = std::any_cast<Output>(value);
}
} // namespace

template <typename Output>
class TaskSuccess : public virtual UntypedTask {
public:
  virtual ~TaskSuccess() = default;

protected:
  void taskSuccess(Output output) {
    ASSERT(!task_success_called_ && !task_failure_called_);
    task_success_called_ = true;
    callbacks_->taskSuccess(output, apply_output<Output>);
  }
};

template <>
class TaskSuccess<void> : public virtual UntypedTask {
public:
  virtual ~TaskSuccess() = default;

protected:
  void taskSuccess() {
    ASSERT(!task_success_called_ && !task_failure_called_);
    task_success_called_ = true;
    callbacks_->taskSuccess({}, {});
  }
};

template <typename Input = void, typename Output = void>
class Task : public virtual UntypedTask,
             public TaskStart<Input>,
             public TaskSuccess<Output> {
  friend class SshConnectionDriver;

public:
  using input_type = Input;
  using output_type = Output;
  Task() = default;
};

template <typename Input = void, typename Output = void>
using TaskPtr = std::unique_ptr<Task<Input, Output>>;

namespace Tasks {

class RequestUserAuthService : public Task<> {
public:
  void start() override {
    callbacks_->sendMessage(wire::ServiceRequestMsg{
      .service_name = "ssh-userauth"s,
    });
  }

  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ServiceAcceptMsg& msg) {
        if (msg.service_name == "ssh-userauth") {
          taskSuccess();
          return Break;
        }
        return Continue;
      },
      DEFAULT_CONTINUE);
  }
};

class Authenticate : public Task<> {
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

  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::UserAuthSuccessMsg&) {
        taskSuccess();
        return Break;
      },
      [&](const wire::UserAuthFailureMsg& msg) {
        taskFailure(absl::InternalError(fmt::format("received auth failure: {}", msg)));
        return Break;
      },
      [&](const wire::UserAuthBannerMsg&) {
        // ignore for now
        return Break;
      },
      DEFAULT_CONTINUE);
  };

  const std::string username_;
  const bool internal_{};
};

class RequestReversePortForward : public Task<> {
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
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::GlobalRequestSuccessMsg& msg) {
        if (msg.resolve<wire::TcpipForwardResponseMsg>().ok()) {
          EXPECT_EQ(server_port_, *msg.response.get<wire::TcpipForwardResponseMsg>().server_port);
          taskSuccess();
          return Break;
        }
        taskFailure(absl::InternalError("received unexpected global request success response"));
        return Break;
      },
      [&](const wire::GlobalRequestFailureMsg& msg) {
        taskFailure(absl::InternalError(fmt::format("request failed: {}", msg)));
        return Break;
      },
      DEFAULT_CONTINUE);
  };

  const std::string address_;
  const uint32_t port_;
  const uint32_t server_port_;
};

class AcceptReversePortForward : public Task<void, uint32_t> {
public:
  AcceptReversePortForward(const std::string& address_connected, uint32_t port_connected,
                           uint32_t local_channel_id)
      : address_connected_(address_connected),
        port_connected_(port_connected),
        local_channel_id_(local_channel_id) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelOpenMsg& open_msg) {
        return open_msg.request.visit(
          [&](const wire::ForwardedTcpipChannelOpenMsg& msg) {
            if (address_connected_ == msg.address_connected &&
                port_connected_ == msg.port_connected) {
              EXPECT_THAT(*msg.originator_address, AnyOf(Eq("127.0.0.1"s), Eq("::1"s)));
              EXPECT_NE(0, *msg.originator_port);
              callbacks_->sendMessage(wire::ChannelOpenConfirmationMsg{
                .recipient_channel = open_msg.sender_channel,
                .sender_channel = local_channel_id_,
                .initial_window_size = wire::ChannelWindowSize,
                .max_packet_size = 131072,
              });
              taskSuccess(*open_msg.sender_channel);
              return Break;
            }
            return Continue;
          },
          DEFAULT_CONTINUE);
      },
      DEFAULT_CONTINUE);
  }

  const std::string address_connected_;
  const uint32_t port_connected_;
  const uint32_t local_channel_id_;
};

class WaitForChannelData : public Task<> {
public:
  WaitForChannelData(uint32_t channel_id, const std::string& expected_data)
      : channel_id_(channel_id),
        expected_data_(expected_data) {}
  void start() override {
    callbacks_->setTimeout(defaultTimeout());
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        if (msg.recipient_channel != channel_id_) {
          return Continue;
        }
        auto view = std::string_view(reinterpret_cast<const char*>(msg.data->data()), msg.data->size());
        if (view.size() >= expected_data_.size()) {
          if (view.starts_with(expected_data_)) {
            expected_data_.clear();
            taskSuccess();
          } else {
            taskFailure(absl::InternalError(fmt::format("channel data did not match: expected '{}', got '{}'", expected_data_, view)));
          }
        } else {
          if (expected_data_.starts_with(view)) {
            expected_data_ = absl::StripPrefix(expected_data_, view);
          } else {
            taskFailure(absl::InternalError(fmt::format("channel data did not match: expected '{}', got '{}'", expected_data_, view)));
          }
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  absl::Status errorDetails() override {
    return absl::InternalError(fmt::format("expected bytes not received: '{}'", absl::CHexEscape(expected_data_)));
  }
  uint32_t channel_id_{};
  std::string expected_data_;
};

class SendChannelData : public Task<uint32_t> {
public:
  SendChannelData(const bytes& data)
      : data_(data) {}
  SendChannelData(const std::string& data)
      : data_(to_bytes(data)) {}
  void start(uint32_t remote_channel_id) override {
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = remote_channel_id,
      .data = data_,
    });
    taskSuccess();
  }
  MiddlewareResult onMessageReceived(wire::Message&) override { return Continue; }

  bytes data_;
};

class WaitForChannelCloseByPeer : public Task<uint32_t> {
public:
  WaitForChannelCloseByPeer(uint32_t channel_id, bool allow_eof = true)
      : channel_id_(channel_id),
        allow_eof_(allow_eof) {}
  void start(uint32_t remote_channel_id) override {
    remote_channel_id_ = remote_channel_id;
    callbacks_->setTimeout(defaultTimeout());
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelCloseMsg& msg) {
        if (msg.recipient_channel != channel_id_) {
          return Continue;
        }
        callbacks_->sendMessage(wire::ChannelCloseMsg{
          .recipient_channel = remote_channel_id_,
        });
        taskSuccess();
        return Break;
      },
      [&](const wire::ChannelEOFMsg& msg) {
        if (msg.recipient_channel != channel_id_) {
          return Continue;
        }
        if (!allow_eof_) {
          taskFailure(absl::InvalidArgumentError(fmt::format("unexpected EOF for channel {}", channel_id_)));
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  const uint32_t channel_id_;
  uint32_t remote_channel_id_;
  const bool allow_eof_;
};

class SendChannelCloseAndWait : public Task<uint32_t> {
public:
  SendChannelCloseAndWait(uint32_t channel_id, bool allow_eof = true)
      : channel_id_(channel_id),
        allow_eof_(allow_eof) {}
  void start(uint32_t remote_channel_id) override {
    remote_channel_id_ = remote_channel_id;
    callbacks_->sendMessage(wire::ChannelCloseMsg{
      .recipient_channel = remote_channel_id_,
    });
    callbacks_->setTimeout(defaultTimeout());
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelCloseMsg& msg) {
        if (msg.recipient_channel != channel_id_) {
          return Continue;
        }
        taskSuccess();
        return Break;
      },
      [&](const wire::ChannelEOFMsg& msg) {
        if (msg.recipient_channel != channel_id_) {
          return Continue;
        }
        if (!allow_eof_) {
          taskFailure(absl::InvalidArgumentError(fmt::format("unexpected EOF for channel {}", channel_id_)));
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  const uint32_t channel_id_;
  uint32_t remote_channel_id_;
  const bool allow_eof_;
};

} // namespace Tasks

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec