#pragma once

#include "source/common/status.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/extension_ping.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/packet_cipher_impl.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

template <typename T>
struct codec_traits;

template <>
struct codec_traits<ServerCodec> {
  using callbacks_type = ServerCodecCallbacks;
  static constexpr direction_t direction_read = clientKeys;
  static constexpr direction_t direction_write = serverKeys;
  static constexpr KexMode kex_mode = KexMode::Server;
};

template <>
struct codec_traits<ClientCodec> {
  using callbacks_type = ClientCodecCallbacks;
  static constexpr direction_t direction_read = serverKeys;
  static constexpr direction_t direction_write = clientKeys;
  static constexpr KexMode kex_mode = KexMode::Client;
};

template <typename Codec>
class TransportBase : public Codec,
                      public KexCallbacks,
                      public SshMessageDispatcher,
                      public SshMessageHandler,
                      public virtual TransportCallbacks,
                      public virtual Logger::Loggable<Logger::Id::filter> {
public:
  TransportBase(Api::Api& api,
                std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
      : api_(api), config_(config) {}
  using Callbacks = codec_traits<Codec>::callbacks_type;

  void setCodecCallbacks(Callbacks& callbacks) override {
    this->callbacks_ = &callbacks;
    this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));
    kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), codec_traits<Codec>::kex_mode);
    kex_->registerMessageHandlers(*this);
    version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_);

    auto defaultState = new ConnectionState{};
    defaultState->cipher = PacketCipherFactory::makeUnencryptedPacketCipher();
    defaultState->direction_read = codec_traits<Codec>::direction_read;
    defaultState->direction_write = codec_traits<Codec>::direction_write;
    defaultState->seq_read = std::make_shared<uint32_t>(0);
    defaultState->seq_write = std::make_shared<uint32_t>(0);
    connection_state_.reset(defaultState);
  }

  void decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) override {
    while (buffer.length() > 0) {
      if (!version_exchange_done_) {
        if (!version_exchanger_->versionRead()) {
          auto stat = version_exchanger_->readVersion(buffer);
          if (!stat.ok()) {
            onDecodingFailure(stat);
            return;
          }
        }
        if (!version_exchanger_->versionWritten()) {
          auto n = version_exchanger_->writeVersion(server_version_);
          if (!n.ok()) {
            onDecodingFailure(n.status());
            return;
          }
        }
        version_exchange_done_ = true;
        continue;
      }

      Envoy::Buffer::OwnedImpl dec;
      auto stat = connection_state_->cipher->decryptPacket(*connection_state_->seq_read, dec, buffer);
      if (!stat.ok()) {
        onDecodingFailure(statusf("failed to decrypt packet: {}", stat));
        return;
      } else if (dec.length() == 0) {
        ENVOY_LOG(debug, "received incomplete packet; waiting for more data");
        return;
      }
      auto prev = (*connection_state_->seq_read)++;
      ENVOY_LOG(trace, "read seqnr inc: {} -> {}", prev, *connection_state_->seq_read);

      wire::Message msg;
      auto n = wire::decodePacket(dec, msg);
      if (!n.ok()) {
        onDecodingFailure(statusf("failed to decode packet: {}", n.status()));
        return;
      }
      if (msg.msg_type() == wire::SshMessageType::NewKeys) {
        ENVOY_LOG(debug, "resetting read sequence number");
        *connection_state_->seq_read = 0;
      }
      ENVOY_LOG(trace, "received message: size: {}, type: {}", *n, msg.msg_type());
      if (auto err = onMessageDecoded(std::move(msg)); !err.ok()) {
        onDecodingFailure(err);
        return;
      }
    }
  }

  void setKexResult(std::shared_ptr<KexResult> kex_result) override {
    kex_result_ = kex_result;

    connection_state_->cipher =
      PacketCipherFactory::makePacketCipher(connection_state_->direction_read,
                                            connection_state_->direction_write,
                                            kex_result.get());
    if (!initial_kex_done_) {
      initial_kex_done_ = true;
      onInitialKexDone();
    }
  }
  const KexResult& getKexResult() const final { return *kex_result_; }
  const ConnectionState& getConnectionState() const final { return *connection_state_; }
  const pomerium::extensions::ssh::CodecConfig& codecConfig() const final { return *config_; }

  void writeToConnection(Envoy::Buffer::Instance& buf) const final {
    return callbacks_->writeToConnection(buf);
  }

  void updatePeerExtInfo(std::optional<wire::ExtInfoMsg> msg) override {
    peer_ext_info_ = std::move(msg);
  }

  std::optional<wire::ExtInfoMsg> outgoingExtInfo() final {
    if (outgoing_ext_info_.has_value()) {
      std::optional<wire::ExtInfoMsg> out;
      outgoing_ext_info_.swap(out);
      return out;
    }
    return {};
  }

  std::optional<wire::ExtInfoMsg> peerExtInfo() const final {
    return {peer_ext_info_};
  }

protected:
  virtual absl::Status onMessageDecoded(wire::Message&& msg) {
    return dispatch(std::move(msg));
  }
  virtual void onInitialKexDone() {
    ENVOY_LOG(debug, "ssh: initial key exchange done");
  }
  virtual void onDecodingFailure(absl::Status err) {
    if (err.ok()) {
      ENVOY_LOG(info, "ssh: stream {} closing", streamId(), err.message());
    } else {
      ENVOY_LOG(error, "ssh: stream {} closing with error: {}", streamId(), err.message());
    }
    callbacks_->onDecodingFailure(err.message());
  }

protected:
  Callbacks* callbacks_;

  Api::Api& api_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;

  std::unique_ptr<VersionExchanger> version_exchanger_;
  std::unique_ptr<Kex> kex_;
  std::shared_ptr<KexResult> kex_result_;
  std::unique_ptr<ConnectionState> connection_state_;
  std::optional<wire::ExtInfoMsg> outgoing_ext_info_;
  std::optional<wire::ExtInfoMsg> peer_ext_info_;

  std::string server_version_{"SSH-2.0-Envoy"};

private:
  bool version_exchange_done_{};
  bool initial_kex_done_{};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec