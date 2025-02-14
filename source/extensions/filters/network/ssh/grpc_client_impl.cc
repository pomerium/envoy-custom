#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "bazel-out/k8-dbg/bin/api/extensions/filters/network/ssh/ssh.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using namespace pomerium::extensions::ssh;

StreamManagementServiceClient::StreamManagementServiceClient(Grpc::RawAsyncClientSharedPtr client)
    : method_manage_stream_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "pomerium.extensions.ssh.StreamManagement.ManageStream")),
      client_(client) {}

StreamManagementServiceClient::~StreamManagementServiceClient() {
  if (stream_ != nullptr) {
    stream_.resetStream();
  }
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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec