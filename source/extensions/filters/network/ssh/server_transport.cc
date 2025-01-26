#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

void SshServerCodec::setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) {
  this->callbacks_ = &callbacks;
}

void SshServerCodec::decode(Envoy::Buffer::Instance& buffer, bool end_stream) {
  (void)end_stream;
  if (!handshake_done_) {
    if (!handshaker_) {
      handshaker_ = std::make_unique<Handshaker>(callbacks_, api_.fileSystem());
    }
    auto [done, err] = handshaker_->decode(buffer);
    if (err) {
      ENVOY_LOG(error, "ssh: {}", err.value());
      callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.value()));
      return;
    }
    handshake_done_ = done;
    return;
  }
  buffer.drain(buffer.length());
  (void)buffer;
}

GenericProxy::EncodingResult SshServerCodec::encode(const GenericProxy::StreamFrame& frame,
                                                    GenericProxy::EncodingContext& ctx) {
  (void)frame;
  (void)ctx;
  return absl::OkStatus();
}
GenericProxy::ResponsePtr SshServerCodec::respond(absl::Status, absl::string_view,
                                                  const GenericProxy::Request&) {
  return nullptr;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec