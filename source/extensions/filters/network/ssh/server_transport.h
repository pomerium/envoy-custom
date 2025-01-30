#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "envoy/filesystem/filesystem.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class Handshaker {
public:
  Handshaker(GenericProxy::ServerCodecCallbacks* callbacks, KexCallbacks& kexCallbacks,
             Filesystem::Instance& fs);
  std::tuple<bool, error> decode(Envoy::Buffer::Instance& buffer) noexcept;

  error doVersionExchange(Envoy::Buffer::Instance& buffer) noexcept;

  error readVersion(Envoy::Buffer::Instance& buffer);

private:
  bool version_exchange_done_{};
  bool initial_kex_done_{};
  bool sent_newkeys_{};
  std::string their_version_;
  std::unique_ptr<Kex> kex_;
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  KexCallbacks& kex_callbacks_;
};

class SshServerCodec : public Logger::Loggable<Logger::Id::filter>,
                       public ServerCodec,
                       public KexCallbacks {
public:
  SshServerCodec(Api::Api& api) : api_(api) { ENVOY_LOG(debug, "constructor"); };
  ~SshServerCodec() { ENVOY_LOG(debug, "destructor"); };
  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void setKexResult(std::shared_ptr<kex_result_t> kex_result) override;

private:
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  bool handshake_done_{};
  std::unique_ptr<Handshaker> handshaker_;
  Api::Api& api_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec