#pragma once
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/service.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SshClientCodec : public Logger::Loggable<Logger::Id::filter>,
                       public ClientCodec,
                       public TransportCallbacks,
                       public KexCallbacks,
                       public MessageDispatcher,
                       public MessageHandler {
public:
  SshClientCodec(Api::Api& api);

  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;

  void setKexResult(std::shared_ptr<kex_result_t> kex_result) override;
  absl::Status handleMessage(AnyMsg&& msg) override;

private:
  const connection_state_t& getConnectionState() const override;
  void writeToConnection(Envoy::Buffer::Instance& buf) const override;

  void initUpstream(std::string_view, std::string_view) override;

  GenericProxy::ClientCodecCallbacks* callbacks_{};
  bool version_exchange_done_{};
  std::unique_ptr<VersionExchanger> version_exchanger_;
  Api::Api& api_;
  std::unique_ptr<Kex> kex_;
  std::unique_ptr<connection_state_t> connection_state_;
  std::map<std::string, std::unique_ptr<Service>> services_;
};
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec