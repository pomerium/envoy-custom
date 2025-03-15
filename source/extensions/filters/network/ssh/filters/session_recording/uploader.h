#pragma once

#include <latch>
#pragma clang unsafe_buffer_usage begin
#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
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
                    Compression::Compressor::CompressorFactoryPtr compressor_factory)
      : config_(config),
        fs_(fs),
        upload_thread_dispatcher_(upload_thread_dispatcher),
        method_recording_finalized_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "pomerium.extensions.ssh.filters.session_recording.RecordingService.RecordingFinalized")),
        compressor_factory_(std::move(compressor_factory)) {
    upload_thread_dispatcher_.post([this, create_grpc_client] {
      auto client = create_grpc_client();
      THROW_IF_NOT_OK_REF(client.status());
      recording_svc_client_ = *client;
    });
  }

  void upload(RecordingMetadata metadata) {
    upload_thread_dispatcher_.post([this, metadata = std::move(metadata)] {
      doUpload(metadata);
    });
  }

private:
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {};
  void onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&&) override {};
  void onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&&) override {};
  void onRemoteClose(Grpc::Status::GrpcStatus, const std::string&) override {};

  void doUpload(const RecordingMetadata& metadata) {
    ASSERT(upload_thread_dispatcher_.isThreadSafe());
    auto absPath = absl::StrJoin({config_->storage_dir(), metadata.recording_name()}, "/");
    if (!fs_.fileExists(absPath)) {
      ENVOY_LOG(error, "recording does not exist on disk: {}", absPath);
      return;
    }
    auto f = fs_.createFile({Filesystem::DestinationType::File, absPath});
    if (auto [ok, err] = f->open(Filesystem::FlagSet{1 << Filesystem::File::Operation::Read}); err) {
      ENVOY_LOG(error, "error opening recording file {} for reading: {}", f->path(), err->getErrorDetails());
      return;
    } else if (!ok) {
      ENVOY_LOG(error, "error opening recording file {} for reading: {}", f->path(), "unknown error");
      return;
    }
    auto [info, err] = f->info();
    if (err) {
      ENVOY_LOG(error, "error getting file info for {}: {}", f->path(), err->getErrorDetails());
      return;
    }

    constexpr size_t chunkSize = 2uz * 1024 * 1024; // 2MB
    size_t fileSize = *info.size_;
    auto numChunks = fileSize / chunkSize + (fileSize % chunkSize != 0 ? 1 : 0);
    ENVOY_LOG(debug, "uploading recording {} in {} chunks ({} total bytes)", metadata.recording_name(), numChunks, metadata.uncompressed_size());

    auto stream = recording_svc_client_.start(method_recording_finalized_, *this,
                                              Http::AsyncClient::StreamOptions());
    // send metadata
    RecordingData md;
    *md.mutable_metadata() = metadata;
    stream.sendMessage(md, false);

    auto compressor = compressor_factory_->createCompressor();
    bssl::ScopedEVP_MD_CTX checksum;
    EVP_DigestInit(checksum.get(), EVP_sha256());

    size_t accum = 0;
    Envoy::Buffer::OwnedImpl buffer;
    for (size_t chunk = 0; chunk < numChunks; chunk++) {
      auto currentChunkSize = std::min(chunkSize, fileSize - accum);
      auto reservation = buffer.reserveSingleSlice(currentChunkSize);
      auto [n, err] = f->pread(reservation.slice().mem_, reservation.slice().len_, accum);
      if (err) {
        ENVOY_LOG(error, "I/O error: {}", err->getErrorDetails());
        stream.resetStream();
        return;
      }
      reservation.commit(n);
      accum += n;
      auto shortRead = (static_cast<size_t>(n) < currentChunkSize);

      compressor->compress(buffer, chunk == numChunks - 1
                                     ? Compression::Compressor::State::Finish
                                     : Compression::Compressor::State::Flush);

      EVP_DigestUpdate(checksum.get(), buffer.linearize(buffer.length()), buffer.length());
      RecordingData data;
      data.mutable_chunk()->resize(buffer.length());
      buffer.copyOut(0, buffer.length(), data.mutable_chunk()->data());
      stream->sendMessage(data, false);
      if (shortRead) {
        ENVOY_LOG(error, "I/O error: short read from {}", f->path());
        stream.resetStream();
        return;
      }
    }

    RecordingData last;
    auto& digest = *last.mutable_checksum();
    digest.resize(EVP_MD_CTX_size(checksum.get()));
    EVP_DigestFinal(checksum.get(), reinterpret_cast<uint8_t*>(digest.data()), nullptr);
    stream.sendMessage(last, true);
    ENVOY_LOG(debug, "finished uploading recording {}", f->path());
  }
  void onReceiveMessage(Grpc::ResponsePtr<ProtobufWkt::Empty>&&) override {}
  std::shared_ptr<Config> config_;
  Envoy::Filesystem::Instance& fs_;
  Envoy::Event::Dispatcher& upload_thread_dispatcher_;
  Grpc::AsyncClient<RecordingData, ProtobufWkt::Empty> recording_svc_client_;
  const Protobuf::MethodDescriptor& method_recording_finalized_;
  Compression::Compressor::CompressorFactoryPtr compressor_factory_;
  std::latch init_wait_{1};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording