#include "source/extensions/filters/network/ssh/grpc_client_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

StreamManagementServiceClient::StreamManagementServiceClient(Grpc::RawAsyncClientSharedPtr client)
    : method_manage_stream_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
        "pomerium.extensions.ssh.StreamManagement.ManageStream")),
      client_(client) {}

Grpc::AsyncStream<ClientMessage>& StreamManagementServiceClient::stream() {
  return stream_;
}

void StreamManagementServiceClient::setOnRemoteCloseCallback(std::function<void(Grpc::Status::GrpcStatus, std::string)> cb) {
  on_remote_close_ = cb;
}

void StreamManagementServiceClient::connect() {
  ClientMessage msg;
  msg.mutable_event()->mutable_downstream_connected();
  stream_ = client_.start(method_manage_stream_, *this, Http::AsyncClient::StreamOptions{});
  stream_.sendMessage(msg, false);
}

void StreamManagementServiceClient::onReceiveMessage(Grpc::ResponsePtr<ServerMessage>&& message) {
  auto stat = dispatch(std::move(message));
  if (!stat.ok()) {
    ENVOY_LOG(error, stat.message());
  }
}

void StreamManagementServiceClient::onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& err) {
  if (on_remote_close_) {
    on_remote_close_(status, err);
  }
  if (stream_ != nullptr) {
    stream_.resetStream();
    stream_ = nullptr;
  }
}

ChannelStreamServiceClient::ChannelStreamServiceClient(Grpc::RawAsyncClientSharedPtr client)
    : method_manage_stream_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
        "pomerium.extensions.ssh.StreamManagement.ServeChannel")),
      client_(client) {}

std::weak_ptr<Grpc::AsyncStream<ChannelMessage>> ChannelStreamServiceClient::start(
  ChannelStreamCallbacks* callbacks, Envoy::OptRef<const envoy::config::core::v3::Metadata> metadata) {
  callbacks_ = callbacks;
  Http::AsyncClient::StreamOptions opts;
  if (metadata.has_value()) {
    opts.setMetadata(*metadata);
  }
  stream_ = std::make_shared<Grpc::AsyncStream<ChannelMessage>>(client_.start(method_manage_stream_, *this, opts));
  return stream_;
}

void ChannelStreamServiceClient::onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) {
  callbacks_->onReceiveMessage(std::move(message));
}

void ChannelStreamServiceClient::onRemoteClose(Grpc::Status::GrpcStatus, const std::string&) {
  if (stream_ != nullptr) {
    stream_->resetStream();
    stream_ = nullptr;
  }
  callbacks_ = nullptr;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec