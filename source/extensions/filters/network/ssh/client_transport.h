#pragma once
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SshClientCodec : public ClientCodec {
public:
  SshClientCodec(Api::Api& api) : api_(api) { (void)api_; }
  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override {
    (void)buffer;
    (void)end_stream;
  }
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override {
    (void)frame;
    (void)ctx;
    return absl::OkStatus();
  }

private:
  GenericProxy::ClientCodecCallbacks* callbacks_{};
  Api::Api& api_;
};
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec