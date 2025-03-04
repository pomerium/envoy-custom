#include "envoy/http/header_map.h"

#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/common/config/metadata.h"

#include "api/extensions/filters/network/ssh/ssh.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

StreamManagementServiceClient::StreamManagementServiceClient(Grpc::RawAsyncClientSharedPtr client)
    : method_manage_stream_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "pomerium.extensions.ssh.StreamManagement.ManageStream")),
      client_(client) {}

StreamManagementServiceClient::~StreamManagementServiceClient() {
  stream_ = nullptr;
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

ChannelStreamServiceClient::ChannelStreamServiceClient(Grpc::RawAsyncClientSharedPtr client)
    : method_manage_stream_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "pomerium.extensions.ssh.StreamManagement.ServeChannel")),
      client_(client) {}

ChannelStreamServiceClient::~ChannelStreamServiceClient() {
  stream_ = nullptr;
}

Grpc::AsyncStream<ChannelMessage>* ChannelStreamServiceClient::start(
    ChannelStreamCallbacks* callbacks, Envoy::OptRef<envoy::config::core::v3::Metadata> metadata) {
  callbacks_ = callbacks;
  metadata_ = metadata;
  Http::AsyncClient::StreamOptions opts;
  ENVOY_LOG(error, "ChannelStreamServiceClient::start");
  /*if (metadata.has_value()) {
    opts.setMetadata(*metadata);
    ENVOY_LOG(error, "metadata: {}", metadata->DebugString());
  }*/
  stream_ = client_.start(method_manage_stream_, *this, opts);
  return &stream_;
}

void ChannelStreamServiceClient::onCreateInitialMetadata(Http::RequestHeaderMap& headers) {
  if (metadata_.has_value()) {
      auto id = Envoy::Config::Metadata::metadataValue(metadata_.ptr(), "pomerium.ssh", "pomerium-session-id");
      ENVOY_LOG(error, "ChannelStreamServiceClient::onCreateInitialMetadata {}", id.string_value());
      headers.setCopy(Http::LowerCaseString("pomerium-session-id"), id.string_value());
  }
}

void ChannelStreamServiceClient::onReceiveMessage(Grpc::ResponsePtr<ChannelMessage>&& message) {
  callbacks_->onReceiveMessage(std::move(message));
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec