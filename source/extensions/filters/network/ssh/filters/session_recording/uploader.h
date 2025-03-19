#pragma once

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "envoy/compression/compressor/factory.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::filters::session_recording::Config;
using pomerium::extensions::ssh::filters::session_recording::RecordingData;
using pomerium::extensions::ssh::filters::session_recording::RecordingMetadata;

class RecordingUploader : Logger::Loggable<Logger::Id::filter>,
                          Grpc::AsyncStreamCallbacks<ProtobufWkt::Empty> {
public:
  RecordingUploader(std::shared_ptr<Config> config,
                    Envoy::Filesystem::Instance& fs,
                    Envoy::Event::Dispatcher& upload_thread_dispatcher,
                    Codec::CreateGrpcClientFunc create_grpc_client,
                    Compression::Compressor::CompressorFactoryPtr compressor_factory);

  void upload(RecordingMetadata metadata);

private:
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {};
  void onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&&) override {};
  void onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&&) override {};
  void onRemoteClose(Grpc::Status::GrpcStatus, const std::string&) override {};

  void doUpload(const RecordingMetadata& metadata);
  void onReceiveMessage(Grpc::ResponsePtr<ProtobufWkt::Empty>&&) override {}
  std::shared_ptr<Config> config_;
  Envoy::Filesystem::Instance& fs_;
  Envoy::Event::Dispatcher& upload_thread_dispatcher_;
  Grpc::AsyncClient<RecordingData, ProtobufWkt::Empty> recording_svc_client_;
  const Protobuf::MethodDescriptor& method_recording_finalized_;
  Compression::Compressor::CompressorFactoryPtr compressor_factory_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording