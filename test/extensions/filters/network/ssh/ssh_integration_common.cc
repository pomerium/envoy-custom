#include "test/extensions/filters/network/ssh/ssh_integration_common.h"
#include "source/common/http/utility.h"
#include "source/common/http/headers.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/buffer/zero_copy_input_stream_impl.h"
#include "source/common/grpc/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

UntypedFakeGrpcStream::UntypedFakeGrpcStream(Http::ResponseEncoder& response_encoder,
                                             absl::AnyInvocable<stream_coroutine(FakeGrpcStream)>& coroutine_fn,
                                             absl::AnyInvocable<void(UntypedFakeGrpcStream*)> on_destroy)
    : response_encoder_(response_encoder),
      on_destroy_(std::move(on_destroy)) {
  response_encoder.getStream().addCallbacks(*this); // TODO?
  coroutine_.emplace(coroutine_fn(FakeGrpcStream(*this)));
}

absl::Status UntypedFakeGrpcStream::RecvMsg(google::protobuf::Message& message) {
  ASSERT(!decoded_grpc_frames_.empty());
  auto& frame = decoded_grpc_frames_.front();
  auto stat = absl::OkStatus();
  if (frame.length_ > 0) {
    Envoy::Buffer::ZeroCopyInputStreamImpl stream(std::move(decoded_grpc_frames_[0].data_));
    ASSERT(decoded_grpc_frames_[0].flags_ == Grpc::GRPC_FH_DEFAULT);
    auto ok = message.ParseFromZeroCopyStream(&stream);
    if (!ok) {
      stat.Update(absl::InvalidArgumentError("received malformed grpc message"));
      ENVOY_LOG(debug, "received malformed grpc message");
    } else {
      ENVOY_LOG(debug, "received grpc message: {}", message.DebugString());
    }
  }
  decoded_grpc_frames_.erase(decoded_grpc_frames_.begin());
  return stat;
}

void UntypedFakeGrpcStream::SendMsg(const google::protobuf::Message& msg) {
  if (!stream_started_) {
    SendHeaders();
  }
  auto frame = Envoy::Grpc::Common::serializeToGrpcFrame(msg);
  response_encoder_.encodeData(*frame, false);
  ENVOY_LOG(debug, "sent grpc message: {}", msg.DebugString());
}

size_t UntypedFakeGrpcStream::BufferedFrameCount() const {
  return decoded_grpc_frames_.size();
}

absl::Status UntypedFakeGrpcStream::Err() const {
  return stream_error_;
}

const Http::RequestHeaderMap& UntypedFakeGrpcStream::Headers() const {
  return *headers_;
}

const Http::MetadataMap& UntypedFakeGrpcStream::Metadata() const {
  return metadata_map_;
}

Envoy::OptRef<const Http::RequestTrailerMap> UntypedFakeGrpcStream::Trailers() const {
  if (trailers_ != nullptr) {
    return *trailers_;
  }
  return std::nullopt;
}

void UntypedFakeGrpcStream::SetHeaders(Http::ResponseHeaderMapPtr headers) {
  response_headers_ = std::move(headers);
}

void UntypedFakeGrpcStream::SetTrailers(Http::ResponseTrailerMapPtr trailers) {
  response_trailers_ = std::move(trailers);
}

void UntypedFakeGrpcStream::SendHeaders() {
  if (!stream_started_) {
    stream_started_ = true;
    if (response_headers_ == nullptr) {
      response_headers_ = Http::ResponseHeaderMapImpl::create();
    }
    response_headers_->setStatus(200);
    response_encoder_.encodeHeaders(*response_headers_, false);
  }
}

void UntypedFakeGrpcStream::ReturnValue(absl::Status err) {
  stream_error_.Update(err);
}

void UntypedFakeGrpcStream::decodeHeaders(Http::RequestHeaderMapSharedPtr&& headers, bool end_stream) {
  headers_ = std::move(headers);
  if (end_stream) {
    stream_error_.Update(absl::CancelledError("EOF"));
  }
  resumeHandler();
}

void UntypedFakeGrpcStream::decodeTrailers(Http::RequestTrailerMapPtr&& trailers) {
  trailers_ = std::move(trailers);
  stream_error_.Update(absl::CancelledError("EOF"));
  resumeHandler();
}

void UntypedFakeGrpcStream::sendLocalReply(Http::Code code, absl::string_view body, const std::function<void(Http::ResponseHeaderMap&)>& /*modify_headers*/,
                                           const absl::optional<Grpc::Status::GrpcStatus> grpc_status, absl::string_view /*details*/) {
  // copied from Envoy::FakeStream

  bool is_head_request =
    is_head_request = headers_ != nullptr &&
                      headers_->getMethodValue() == Http::Headers::get().MethodValues.Head;

  Http::Utility::sendLocalReply(
    false,
    Http::Utility::EncodeFunctions(
      {nullptr, nullptr,
       [&](Http::ResponseHeaderMapPtr&& headers, bool end_stream) -> void {
         response_encoder_.encodeHeaders(*headers, end_stream);
       },
       [&](Buffer::Instance& data, bool end_stream) -> void {
         response_encoder_.encodeData(data, end_stream);
       }}),
    Http::Utility::LocalReplyData({false, code, body, grpc_status, is_head_request}));
}

StreamInfo::StreamInfo& UntypedFakeGrpcStream::streamInfo() {
  RELEASE_ASSERT(false, "initialize if this is needed");
  return *stream_info_;
}

AccessLog::InstanceSharedPtrVector UntypedFakeGrpcStream::accessLogHandlers() {
  return access_log_handlers_;
}

Http::RequestDecoderHandlePtr UntypedFakeGrpcStream::getRequestDecoderHandle() {
  return std::make_unique<RequestDecoderHandle>(*this);
}

void UntypedFakeGrpcStream::decodeData(Buffer::Instance& data, bool end_stream) {
  auto stat = grpc_decoder_.decode(data, decoded_grpc_frames_);
  if (!stat.ok()) {
    stream_error_.Update(stat);
  } else if (end_stream) {
    stream_error_.Update(absl::CancelledError("EOF"));
  }
  resumeHandler();
}

void UntypedFakeGrpcStream::decodeMetadata(Http::MetadataMapPtr&& metadata_map) {
  for (const auto& metadata : *metadata_map) {
    metadata_map_.insert(metadata);
  }
}

void UntypedFakeGrpcStream::onResetStream(Http::StreamResetReason reason,
                                          absl::string_view transport_failure_reason) {
  stream_error_ = absl::AbortedError(fmt::format("stream reset ({}): {}",
                                                 std::to_underlying(reason), transport_failure_reason));
  resumeHandler();
}

void UntypedFakeGrpcStream::resumeHandler() {
  coroutine_->resume();
  absl::Status status;
  if (coroutine_->done()) {
    auto s = coroutine_->promise().status_;
    if (s.has_value()) {
      status = *s;
    } else {
      ASSERT(coroutine_->promise().exception_ != nullptr);
      try {
        std::rethrow_exception(coroutine_->promise().exception_);
      } catch (const std::exception& ex) {
        status = absl::InternalError(fmt::format("handler threw an exception: {}", ex.what()));
      }
    }

    if (!stream_started_) {
      SendHeaders();
    }
    if (response_trailers_ == nullptr) {
      response_trailers_ = Envoy::Http::ResponseTrailerMapImpl::create();
    }
    response_trailers_->setGrpcStatus(std::to_string(status.raw_code()));
    response_trailers_->setGrpcMessage(status.message());
    response_encoder_.encodeTrailers(*response_trailers_);
    coroutine_->destroy();
    response_encoder_.getStream().removeCallbacks(*this);
    on_destroy_(this);
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec