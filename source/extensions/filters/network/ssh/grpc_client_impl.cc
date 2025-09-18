#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/common/status.h"

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

void StreamManagementServiceClient::connect(stream_id_t stream_id) {
  ClientMessage msg;
  msg.mutable_event()->mutable_downstream_connected()->set_stream_id(stream_id);
  stream_ = client_.start(method_manage_stream_, *this, Http::AsyncClient::StreamOptions{});
  ASSERT(stream_ != nullptr);
  stream_.sendMessage(msg, false);
}

void StreamManagementServiceClient::onReceiveMessage(Grpc::ResponsePtr<ServerMessage>&& message) {
  auto stat = dispatch(std::move(message));
  if (!stat.ok()) {
    ENVOY_LOG(error, stat.message());
    if (on_remote_close_ && !on_remote_close_called_) {
      on_remote_close_called_ = true;
      on_remote_close_(static_cast<Grpc::Status::GrpcStatus>(stat.code()), std::string(stat.message()));
    }
  }
}

void StreamManagementServiceClient::onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& err) {
  stream_ = nullptr;
  if (on_remote_close_ && !on_remote_close_called_) {
    on_remote_close_called_ = true;
    on_remote_close_(status, err);
  }
}

ChannelStreamServiceClient::ChannelStreamServiceClient(Grpc::RawAsyncClientSharedPtr client)
    : method_manage_stream_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
        "pomerium.extensions.ssh.StreamManagement.ServeChannel")),
      client_(client) {}

ChannelStreamServiceClient::~ChannelStreamServiceClient() {
  if (stream_ != nullptr) {
    stream_.resetStream();
  }
}

void ChannelStreamServiceClient::start(ChannelStreamCallbacks* callbacks, envoy::config::core::v3::Metadata metadata) {
  callbacks_ = callbacks;
  Http::AsyncClient::StreamOptions opts;
  ASSERT(stream_ == nullptr);
  stream_ = client_.start(method_manage_stream_, *this, opts);
  if (stream_ != nullptr) {
    ChannelMessage mdMsg;
    *mdMsg.mutable_metadata() = std::move(metadata);
    stream_->sendMessage(mdMsg, false);
  } else {
    // if stream_ is nullptr, onRemoteClose will already have been called.
    ASSERT(callbacks_ == nullptr);
  }
}

void ChannelStreamServiceClient::sendMessage(const ChannelMessage& message) {
  ASSERT(stream_ != nullptr);
  stream_->sendMessage(message, false);
}

void ChannelStreamServiceClient::onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) {
  auto stat = callbacks_->onReceiveMessage(std::move(message));
  if (!stat.ok()) {
    ENVOY_LOG(error, "error returned by grpc client callback; closing stream: {}", statusToString(stat));
    stream_.resetStream();
    stream_ = nullptr;
    notifyOnStreamClosedOnce(stat);
  }
}

void ChannelStreamServiceClient::onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& err) {
  stream_ = nullptr;
  notifyOnStreamClosedOnce(absl::Status(static_cast<absl::StatusCode>(status), err));
}

void ChannelStreamServiceClient::notifyOnStreamClosedOnce(absl::Status stat) {
  ASSERT(stream_ == nullptr);
  if (callbacks_ != nullptr) {
    if (!stat.ok()) {
      ENVOY_LOG(warn, "grpc stream closed by remote with error: {}", statusToString(stat));
    } else {
      ENVOY_LOG(debug, "grpc stream closed by remote");
    }
    callbacks_->onStreamClosed(stat);
    callbacks_ = nullptr;
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec