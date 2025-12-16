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

#define DEFAULT_NOOP \
  [&](const auto&) {}

#define DEFAULT_BREAK \
  [&](const auto&) { return MiddlewareResult::Break; }

#define DEFAULT_CONTINUE \
  [&](const auto&) { return MiddlewareResult::Continue; }

class TaskCallbacks {
  template <typename, typename>
  friend class Task;
  template <typename>
  friend class TaskSuccess;
  friend class UntypedTask;

public:
  virtual ~TaskCallbacks() = default;
  virtual void sendMessage(wire::Message&&) PURE;
  // Starts a timer that will call taskFailure() after the timeout, unless taskSuccess() has been
  // called before the timer elapses.
  virtual void setTimeout(std::chrono::milliseconds timeout, const std::string& name) PURE;
  // Starts a timer that will invoke the given callback after the timeout, unless taskSuccess() or
  // taskFailure() have been called before the timer elapses.
  virtual void setTimeout(std::chrono::milliseconds timeout, std::function<void()> cb) PURE;
  virtual void loop(std::chrono::milliseconds interval, std::function<void()> cb) PURE;

private:
  virtual void taskSuccess(std::any output, std::function<void(const std::any&, void*)> apply_fn) PURE;
  virtual void taskFailure(absl::Status err) PURE;
};

namespace Tasks {
struct Channel {
  uint32_t local_id;
  uint32_t remote_id;

  uint32_t initial_window_size;
  uint32_t max_packet_size;

  uint32_t upstream_initial_window_size;
  uint32_t upstream_max_packet_size;

  bool initialized{};
};
} // namespace Tasks

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
  virtual std::string errorDetails() {
    return "no details";
  }

  void taskFailure(absl::Status err) {
    RELEASE_ASSERT(!task_success_called_ && !task_failure_called_, "");
    task_failure_called_ = true;
    callbacks_->taskFailure(err);
  }

  TaskCallbacks* callbacks_;
  stream_id_t stream_id_;
  std::chrono::milliseconds default_timeout_;

  bool task_success_called_{};
  bool task_failure_called_{};

  void setChannelFilter(Tasks::Channel c) {
    channel_filter_ = c;
  }

private:
  void startInternalUntyped(std::any input) {
    startUntyped(std::move(input));
    if (testing::Test::HasFailure()) {
      taskFailure(absl::InternalError(fmt::format("task failed via assertion ({})", errorDetails())));
    }
  }
  absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) final {
    bool filtered{};
    msg.visit(
      [&](wire::ChannelMsg auto& msg) {
        if (!channel_filter_.has_value() || *msg.recipient_channel != channel_filter_.value().local_id) {
          filtered = true;
        }
      },
      [](auto&) {});
    if (filtered) {
      return Continue;
    }
    auto res = onMessageReceived(msg);
    RELEASE_ASSERT((res & MiddlewareResult::UninstallSelf) == 0,
                   "Do not return MiddlewareResult::UninstallSelf from Task::interceptMessage; "
                   "call taskSuccess() or taskFailure() instead.");
    if (testing::Test::HasFailure() && !task_success_called_ && !task_failure_called_) {
      taskFailure(absl::InternalError(fmt::format("task failed via assertion ({})", errorDetails())));
    }
    if (task_success_called_ || task_failure_called_) {
      res |= MiddlewareResult::UninstallSelf;
    }
    return res;
  }

  std::optional<Tasks::Channel> channel_filter_;
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
    RELEASE_ASSERT(!task_success_called_ && !task_failure_called_, "");
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
    RELEASE_ASSERT(!task_success_called_ && !task_failure_called_, "");
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

class WaitForUserAuthSuccess : public Task<> {
public:
  void start() override {
    callbacks_->setTimeout(default_timeout_, "WaitForUserAuthSuccess");
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
};

template <typename T>
class WaitForGlobalRequestSuccess : public Task<> {
public:
  void start() override {
    callbacks_->setTimeout(default_timeout_, fmt::format("WaitForGlobalRequestSuccess({})", type_name<T>()));
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::GlobalRequestSuccessMsg& msg) {
        if (msg.resolve<T>().ok()) {
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
};

class AcceptReversePortForward : public Task<void, Channel> {
public:
  AcceptReversePortForward(const std::string& address_connected, uint32_t port_connected,
                           uint32_t local_channel_id)
      : address_connected_(address_connected),
        port_connected_(port_connected),
        local_channel_id_(local_channel_id) {}
  void start() override {
    callbacks_->setTimeout(default_timeout_, fmt::format("AcceptReversePortForward({},{},{})",
                                                         address_connected_, port_connected_, local_channel_id_));
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
                .max_packet_size = wire::ChannelMaxPacketSize,
              });
              taskSuccess(Channel{
                .local_id = local_channel_id_,
                .remote_id = open_msg.sender_channel,
                .initial_window_size = open_msg.initial_window_size,
                .max_packet_size = open_msg.max_packet_size,
                .upstream_initial_window_size = wire::ChannelWindowSize,
                .upstream_max_packet_size = wire::ChannelMaxPacketSize,
              });
              return Break;
            } else {
              details_ = fmt::format("last received open request: {}", msg);
            }
            return Continue;
          },
          DEFAULT_CONTINUE);
      },
      DEFAULT_CONTINUE);
  }

  std::string errorDetails() override {
    if (details_.empty()) {
      return "channel open was never received";
    } else {
      return fmt::format("channel open was received, but did not match: {}", details_);
    }
  }

  std::string details_;
  const std::string address_connected_;
  const uint32_t port_connected_;
  const uint32_t local_channel_id_;
};

class RejectReversePortForward : public Task<> {
public:
  RejectReversePortForward(const std::string& address_connected, uint32_t port_connected)
      : address_connected_(address_connected),
        port_connected_(port_connected) {}
  void start() override {
    callbacks_->setTimeout(default_timeout_, fmt::format("RejectReversePortForward({},{})",
                                                         address_connected_, port_connected_));
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
              callbacks_->sendMessage(wire::ChannelOpenFailureMsg{
                .recipient_channel = open_msg.sender_channel,
              });
              taskSuccess();
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
};

class WaitForChannelData : public Task<Channel, Channel> {
public:
  explicit WaitForChannelData(const std::string& expected_data)
      : expected_data_(expected_data) {}
  void start(Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_, fmt::format("WaitForChannelData({})", expected_data_));
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelDataMsg& msg) {
        auto view = std::string_view(reinterpret_cast<const char*>(msg.data->data()), msg.data->size());
        if (view.size() >= expected_data_.size()) {
          if (view.starts_with(expected_data_)) {
            expected_data_.clear();
            taskSuccess(channel_);
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
  std::string errorDetails() override {
    return fmt::format("expected bytes not received: '{}'", absl::CHexEscape(expected_data_));
  }
  Channel channel_{};
  std::string expected_data_;
};

template <wire::ChannelMsg T>
class WaitForChannelMsg : public Task<Channel, T> {
public:
  WaitForChannelMsg(uint32_t count = 1)
      : count_(count) {}
  void start(Channel channel) override {
    channel_ = channel;
    this->setChannelFilter(channel);
    this->callbacks_->setTimeout(this->default_timeout_, fmt::format("WaitForChannelMsg<{}>({})", type_name<T>(), count_));
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const T& msg) {
        count_--;
        if (count_ == 0) {
          this->taskSuccess(msg);
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  Channel channel_{};
  uint32_t count_{};
};

class SendChannelData : public Task<Channel, Channel> {
public:
  explicit SendChannelData(const bytes& data)
      : data_(data) {}
  explicit SendChannelData(const std::string& data)
      : data_(to_bytes(data)) {}
  void start(Channel channel) override {
    callbacks_->sendMessage(wire::ChannelDataMsg{
      .recipient_channel = channel.remote_id,
      .data = data_,
    });
    taskSuccess(channel);
  }
  MiddlewareResult onMessageReceived(wire::Message&) override { return Continue; }

  bytes data_;
};

class SendWindowAdjust : public Task<Channel, Channel> {
public:
  explicit SendWindowAdjust(uint32_t bytes_to_add)
      : bytes_to_add_(bytes_to_add) {}
  void start(Channel channel) override {
    callbacks_->sendMessage(wire::ChannelWindowAdjustMsg{
      .recipient_channel = channel.remote_id,
      .bytes_to_add = bytes_to_add_,
    });
    taskSuccess(channel);
  }
  MiddlewareResult onMessageReceived(wire::Message&) override { return Continue; }

  uint32_t bytes_to_add_;
};

class SendChannelEOF : public Task<Channel, Channel> {
public:
  void start(Channel channel) override {
    callbacks_->sendMessage(wire::ChannelEOFMsg{
      .recipient_channel = channel.remote_id,
    });
    taskSuccess(channel);
  }
  MiddlewareResult onMessageReceived(wire::Message&) override { return Continue; }
};

enum class ExpectEOF {
  Optional = 0,
  Yes = 1,
  No = 2,
};

enum class SendEOF : bool {};

class WaitForChannelCloseByPeer : public Task<Channel> {
public:
  explicit WaitForChannelCloseByPeer(ExpectEOF expect_eof = ExpectEOF::Optional)
      : eof_requirement_(expect_eof) {}
  void start(Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_, "WaitForChannelCloseByPeer");
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelCloseMsg&) {
        if (eof_requirement_ == ExpectEOF::Yes && !eof_received_) {
          taskFailure(absl::InvalidArgumentError(fmt::format("expected EOF before close for channel {}", channel_.local_id)));
        }
        callbacks_->sendMessage(wire::ChannelCloseMsg{
          .recipient_channel = channel_.remote_id,
        });
        taskSuccess();
        return Break;
      },
      [&](const wire::ChannelEOFMsg&) {
        if (eof_received_) {
          taskFailure(absl::InvalidArgumentError("EOF received twice"));
          return Break;
        }
        if (eof_requirement_ == ExpectEOF::No) {
          taskFailure(absl::InvalidArgumentError(fmt::format("unexpected EOF for channel {}", channel_.local_id)));
        }
        eof_received_ = true;
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  Channel channel_{};
  bool eof_received_{false};
  const ExpectEOF eof_requirement_;
};

class WaitForChannelEOF : public Task<Channel, Channel> {
public:
  void start(Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    callbacks_->setTimeout(default_timeout_, "WaitForChannelEOF");
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelEOFMsg&) {
        taskSuccess(channel_);
        return Break;
      },
      [&](const wire::ChannelCloseMsg&) {
        taskFailure(absl::InternalError("expecting EOF, but got channel close"));
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  Channel channel_{};
};

class SendChannelCloseAndWait : public Task<Channel> {
public:
  SendChannelCloseAndWait(SendEOF send_eof = SendEOF(false), ExpectEOF expect_eof = ExpectEOF::Optional)
      : send_eof_(send_eof),
        eof_requirement_(expect_eof) {}
  void start(Channel channel) override {
    channel_ = channel;
    setChannelFilter(channel);
    if (send_eof_ == SendEOF(true)) {
      callbacks_->sendMessage(wire::ChannelEOFMsg{
        .recipient_channel = channel_.remote_id,
      });
    }
    callbacks_->sendMessage(wire::ChannelCloseMsg{
      .recipient_channel = channel_.remote_id,
    });
    callbacks_->setTimeout(default_timeout_, "SendChannelCloseAndWait");
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](const wire::ChannelCloseMsg&) {
        if (eof_requirement_ == ExpectEOF::Yes && !eof_received_) {
          taskFailure(absl::InvalidArgumentError(fmt::format("expected EOF before close for channel {}", channel_.local_id)));
        }
        taskSuccess();
        return Break;
      },
      [&](const wire::ChannelEOFMsg&) {
        if (eof_requirement_ == ExpectEOF::No) {
          taskFailure(absl::InvalidArgumentError(fmt::format("unexpected EOF for channel {}", channel_.local_id)));
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }
  Channel channel_{};
  const SendEOF send_eof_;
  bool eof_received_{false};
  const ExpectEOF eof_requirement_;
};

class WaitForDisconnectWithError : public Task<> {
public:
  WaitForDisconnectWithError(const std::string& message)
      : message_(message) {}
  void start() override {
    callbacks_->setTimeout(default_timeout_, fmt::format("WaitForDisconnectWithError({})", message_));
  }
  MiddlewareResult onMessageReceived(wire::Message& msg) override {
    return msg.visit(
      [&](wire::DisconnectMsg& disconnect) {
        if (disconnect.description->contains(message_)) {
          taskSuccess();
        } else {
          taskFailure(absl::InternalError(fmt::format(
            "disconnect message '{}' did not contain the expected string '{}'",
            disconnect.description, message_)));
        }
        return Break;
      },
      DEFAULT_CONTINUE);
  }

  const std::string message_;
};

} // namespace Tasks

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec