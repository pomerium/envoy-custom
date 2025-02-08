#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class DownstreamCallbacks;

class ServerTransportCallbacks {
public:
  virtual ~ServerTransportCallbacks() = default;
  virtual DownstreamCallbacks& downstream() PURE;
};

struct connection_state_t {
  std::unique_ptr<PacketCipher> cipher;
  std::shared_ptr<uint32_t> seq_read;
  std::shared_ptr<uint32_t> seq_write;
  direction_t direction_read;
  direction_t direction_write;
  // todo: pending key change?
};

class SshServerCodec : public Logger::Loggable<Logger::Id::filter>,
                       public ServerCodec,
                       public KexCallbacks,
                       public ServerTransportCallbacks,
                       public MessageDispatcher,
                       public MessageHandler {
  friend class DownstreamCallbacks;

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

  DownstreamCallbacks& downstream() override;

private:
  error handleMessage(AnyMsg&& msg) override;

  GenericProxy::ServerCodecCallbacks* callbacks_{};
  bool version_exchange_done_{};
  std::unique_ptr<VersionExchanger> handshaker_;
  Api::Api& api_;

  std::unique_ptr<Kex> kex_;
  std::unique_ptr<connection_state_t> connection_state_;
  std::map<std::string, std::unique_ptr<Service>> services_;

  std::unique_ptr<DownstreamCallbacks> dsc_;
};

class DownstreamCallbacks {
  friend class SshServerCodec;

public:
  error sendMessage(const SshMsg& msg);

private:
  DownstreamCallbacks(SshServerCodec* impl) : impl_(impl) {}
  SshServerCodec* impl_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec