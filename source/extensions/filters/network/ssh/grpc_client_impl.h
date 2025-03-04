#pragma once

#include <type_traits>

#include "source/common/grpc/typed_async_client.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/message_handler.h"

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
  ~StreamManagementServiceClient() override;

  void connect();

  Grpc::AsyncStream<ClientMessage>& stream() {
    return stream_;
  }
  void setOnRemoteCloseCallback(std::function<void(Grpc::Status::GrpcStatus, std::string)> cb) {
    on_remote_close_ = cb;
  }

private:
  void onReceiveMessage(Grpc::ResponsePtr<ServerMessage>&& message) override;
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
  void onReceiveInitialMetadata([[maybe_unused]] Http::ResponseHeaderMapPtr&&) override {}
  void onReceiveTrailingMetadata([[maybe_unused]] Http::ResponseTrailerMapPtr&&) override {}
  void onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& err) override {
    if (on_remote_close_) {
      on_remote_close_(status, err);
    }
    stream_.resetStream();
  }
  const Protobuf::MethodDescriptor& method_manage_stream_;
  Grpc::AsyncStream<ClientMessage> stream_;
  Grpc::AsyncClient<ClientMessage, ServerMessage> client_;
  std::function<void(Grpc::Status::GrpcStatus, std::string)> on_remote_close_;
};

class ChannelStreamCallbacks {
public:
  virtual ~ChannelStreamCallbacks() = default;
  virtual void onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) PURE;
};

class ChannelStreamServiceClient : public Grpc::AsyncStreamCallbacks<ChannelMessage>,
                                   public Logger::Loggable<Logger::Id::filter> {
public:
  ChannelStreamServiceClient(Grpc::RawAsyncClientSharedPtr client);
  ~ChannelStreamServiceClient() override;
  Grpc::AsyncStream<ChannelMessage>* start(ChannelStreamCallbacks* callbacks,
                                           Envoy::OptRef<envoy::config::core::v3::Metadata> metadata);

private:
  void onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) override;
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
  void onReceiveInitialMetadata([[maybe_unused]] Http::ResponseHeaderMapPtr&&) override {}
  void onReceiveTrailingMetadata([[maybe_unused]] Http::ResponseTrailerMapPtr&&) override {}
  void onRemoteClose(Grpc::Status::GrpcStatus, const std::string&) override {
    stream_.resetStream();
    callbacks_ = nullptr;
  }
  const Protobuf::MethodDescriptor& method_manage_stream_;
  Grpc::AsyncStream<ChannelMessage> stream_;
  Grpc::AsyncClient<ChannelMessage, ChannelMessage> client_;
  ChannelStreamCallbacks* callbacks_;
  Envoy::OptRef<envoy::config::core::v3::Metadata> metadata_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec