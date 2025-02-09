#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class ServerDownstreamCallbacks;
class ServerUpstreamCallbacks;

class SshServerCodec : public Logger::Loggable<Logger::Id::filter>,
                       public ServerCodec,
                       public KexCallbacks,
                       public TransportCallbacks,
                       public MessageDispatcher,
                       public MessageHandler {
public:
  SshServerCodec(Api::Api& api);
  ~SshServerCodec() = default;
  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void setKexResult(std::shared_ptr<kex_result_t> kex_result) override;
  void initUpstream(std::string_view username, std::string_view hostname) override;

private:
  absl::Status handleMessage(AnyMsg&& msg) override;
  const connection_state_t& getConnectionState() const override;
  void writeToConnection(Envoy::Buffer::Instance& buf) const override;

  GenericProxy::ServerCodecCallbacks* callbacks_{};
  bool version_exchange_done_{};
  std::unique_ptr<VersionExchanger> handshaker_;
  Api::Api& api_;

  std::unique_ptr<Kex> kex_;
  std::unique_ptr<connection_state_t> connection_state_;
  std::map<std::string, std::unique_ptr<Service>> services_;

  std::string server_version_{"SSH-2.0-Envoy"};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec