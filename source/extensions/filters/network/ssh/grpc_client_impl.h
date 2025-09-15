#pragma once

#include <type_traits>

#pragma clang unsafe_buffer_usage begin
#include "source/common/grpc/typed_async_client.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace pomerium::extensions::ssh {
inline constexpr auto format_as(ServerMessage::MessageCase mt) {
  return fmt::underlying(mt);
}
} // namespace pomerium::extensions::ssh

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using pomerium::extensions::ssh::ChannelMessage;
using pomerium::extensions::ssh::ClientMessage;
using pomerium::extensions::ssh::ServerMessage;

using StreamMgmtServerMessageDispatcher = MessageDispatcher<Grpc::ResponsePtr<ServerMessage>>;
using StreamMgmtServerMessageHandler = MessageHandler<Grpc::ResponsePtr<ServerMessage>>;

template <>
struct message_case_type<Grpc::ResponsePtr<ServerMessage>>
    : std::type_identity<ServerMessage::MessageCase> {};

template <>
inline ServerMessage::MessageCase messageCase(const Grpc::ResponsePtr<ServerMessage>& msg) {
  return msg->message_case();
}

using CreateGrpcClientFunc = std::function<absl::StatusOr<Grpc::RawAsyncClientSharedPtr>(void)>;

class StreamManagementServiceClient : public Grpc::AsyncStreamCallbacks<ServerMessage>,
                                      public StreamMgmtServerMessageDispatcher,
                                      public Logger::Loggable<Logger::Id::filter> {
public:
  StreamManagementServiceClient(Grpc::RawAsyncClientSharedPtr client);

  void connect(stream_id_t stream_id);

  Grpc::AsyncStream<ClientMessage>& stream();
  void setOnRemoteCloseCallback(std::function<void(Grpc::Status::GrpcStatus, std::string)> cb);
  void onReceiveMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;

private:
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
  void onReceiveInitialMetadata([[maybe_unused]] Http::ResponseHeaderMapPtr&&) override {}
  void onReceiveTrailingMetadata([[maybe_unused]] Http::ResponseTrailerMapPtr&&) override {}
  void onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& err) override;
  const Protobuf::MethodDescriptor& method_manage_stream_;
  Grpc::AsyncStream<ClientMessage> stream_;
  Grpc::AsyncClient<ClientMessage, ServerMessage> client_;
  std::function<void(Grpc::Status::GrpcStatus, std::string)> on_remote_close_;
  bool on_remote_close_called_{};
};

class ChannelStreamCallbacks {
public:
  virtual ~ChannelStreamCallbacks() = default;
  virtual absl::Status onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) PURE;
  virtual void onStreamClosed(absl::Status) PURE;
};

class ChannelStreamServiceClient : public Grpc::AsyncStreamCallbacks<ChannelMessage>,
                                   public Logger::Loggable<Logger::Id::filter> {
public:
  ChannelStreamServiceClient(Grpc::RawAsyncClientSharedPtr client);
  void start(ChannelStreamCallbacks* callbacks, envoy::config::core::v3::Metadata metadata);
  void onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) override;
  void sendMessage(const ChannelMessage& message);

private:
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
  void onReceiveInitialMetadata([[maybe_unused]] Http::ResponseHeaderMapPtr&&) override {}
  void onReceiveTrailingMetadata([[maybe_unused]] Http::ResponseTrailerMapPtr&&) override {}
  void onRemoteClose(Grpc::Status::GrpcStatus, const std::string&) override;
  void notifyOnStreamClosedOnce(absl::Status stat);

  const Protobuf::MethodDescriptor& method_manage_stream_;
  Grpc::AsyncClient<ChannelMessage, ChannelMessage> client_; // holds a reference to the client shared_ptr
  Grpc::AsyncStream<ChannelMessage> stream_;
  ChannelStreamCallbacks* callbacks_;
  std::optional<envoy::config::core::v3::Metadata> metadata_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec