#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
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
  std::string their_version_;
  std::unique_ptr<Kex> kex_;
  GenericProxy::ServerCodecCallbacks* callbacks_{};
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
                       public KexCallbacks {
public:
  SshServerCodec(Api::Api& api);
  ~SshServerCodec() { ENVOY_LOG(debug, "destructor"); };
  void setCodecCallbacks(GenericProxy::ServerCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;
  GenericProxy::ResponsePtr respond(absl::Status, absl::string_view,
                                    const GenericProxy::Request&) override;

  void setKexResult(std::shared_ptr<kex_result_t> kex_result) override;

  error handleTransportMsg(AnyMsg&& msg);

private:
  template <typename T>
  std::enable_if_t<std::is_base_of_v<SshMsg<T>, T>, error> sendMsgDownstream(const T& msg) {
    if (!connection_state_) {
      throw EnvoyException("bug: no connection state ");
    }
    Envoy::Buffer::OwnedImpl dec;
    writePacket(dec, msg, connection_state_->cipher->blockSize(MODE_WRITE),
                connection_state_->cipher->aadSize(MODE_WRITE));
    Envoy::Buffer::OwnedImpl enc;
    if (auto err =
            connection_state_->cipher->encryptPacket(*connection_state_->seq_write, enc, dec);
        err.has_value()) {
      return err;
    }
    (*connection_state_->seq_write)++;

    callbacks_->writeToConnection(enc);
    return std::nullopt;
  }
  GenericProxy::ServerCodecCallbacks* callbacks_{};
  bool handshake_done_{};
  std::unique_ptr<Handshaker> handshaker_;
  Api::Api& api_;

  std::unique_ptr<connection_state_t> connection_state_;
  std::map<std::string, std::unique_ptr<Service>> services_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec