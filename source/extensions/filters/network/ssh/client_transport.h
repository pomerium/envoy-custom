#pragma once
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/service.h"
#include <sshkey.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UserAuthService;
class ConnectionService;

class SshClientCodec : public virtual Logger::Loggable<Logger::Id::filter>,
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
  absl::StatusOr<bytearray> signWithHostKey(Envoy::Buffer::Instance& in) const override;
  const downstream_state_t& getDownstreamState() const override;
  void forward(std::unique_ptr<SSHStreamFrame> frame) override;

private:
  const connection_state_t& getConnectionState() const override;
  const kex_result_t& getKexResult() const override;
  void writeToConnection(Envoy::Buffer::Instance& buf) const override;

  void initUpstream(std::shared_ptr<downstream_state_t>) override;

  GenericProxy::ClientCodecCallbacks* callbacks_{};
  bool version_exchange_done_{};
  bool first_kex_done_{};
  std::unique_ptr<VersionExchanger> version_exchanger_;
  std::shared_ptr<kex_result_t> kex_result_;
  Api::Api& api_;
  std::unique_ptr<Kex> kex_;
  std::unique_ptr<connection_state_t> connection_state_;
  std::shared_ptr<downstream_state_t> downstream_state_;
  std::unique_ptr<UserAuthService> user_auth_svc_;
  std::unique_ptr<ConnectionService> connection_svc_;
  std::map<std::string, Service*> services_;
};
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec