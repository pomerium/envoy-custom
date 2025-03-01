#pragma once

#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

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
                std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                AccessLog::AccessLogFileSharedPtr access_log)
      : api_(api), config_(config), access_log_(access_log) {}
  using Callbacks = codec_traits<Codec>::callbacks_type;

  void setCodecCallbacks(Callbacks& callbacks) override {
    this->callbacks_ = &callbacks;
    this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));
    kex_ = std::make_unique<Kex>(*this, *this, api_.fileSystem(), codec_traits<Codec>::kex_mode);
    kex_->registerMessageHandlers(*this);
    version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_);

    auto defaultState = new connection_state_t{};
    defaultState->cipher = newUnencrypted();
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
            ENVOY_LOG(error, "ssh: {}", stat.message());
            callbacks_->onDecodingFailure(stat.message());
            return;
          }
        }
        if (!version_exchanger_->versionWritten()) {
          auto n = version_exchanger_->writeVersion(server_version_);
          if (!n.ok()) {
            ENVOY_LOG(error, "ssh: {}", n.status().message());
            callbacks_->onDecodingFailure(fmt::format("ssh: {}", n.status().message()));
            return;
          }
        }
        version_exchange_done_ = true;
        continue;
      }

      Envoy::Buffer::OwnedImpl dec;
      auto stat = connection_state_->cipher->decryptPacket(*connection_state_->seq_read, dec, buffer);
      if (!stat.ok()) {
        ENVOY_LOG(error, "ssh: decryptPacket: {}", stat.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: decryptPacket: {}", stat.message()));
        return;
      } else if (dec.length() == 0) {
        ENVOY_LOG(debug, "received incomplete packet; waiting for more data");
        return;
      }
      auto prev = (*connection_state_->seq_read)++;
      ENVOY_LOG(debug, "read seqnr inc: {} -> {}", prev, *connection_state_->seq_read);

      wire::AnyMsg anyMsg;
      auto n = wire::decodePacket<wire::AnyMsg>(dec, anyMsg);
      if (!n.ok()) {
        ENVOY_LOG(error, "ssh: readPacket: {}", n.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: readPacket: {}", n.status().message()));
        return;
      }
      auto msg = anyMsg.unwrap();
      if (!msg.ok()) {
        ENVOY_LOG(error, "ssh: error decoding message: {}", msg.status().message());
        callbacks_->onDecodingFailure(fmt::format("ssh: error decoding message: {}", msg.status().message()));
        return;
      }
      if ((*msg)->msg_type() == wire::SshMessageType::NewKeys) {
        ENVOY_LOG(debug, "resetting read sequence number");
        *connection_state_->seq_read = 0;
      }
      ENVOY_LOG(debug, "received message: size: {}, type: {}", *n, (*msg)->msg_type());
      if (auto err = onMessageDecoded(std::move(**msg)); !err.ok()) {
        ENVOY_LOG(error, "ssh: {}", err.message());
        callbacks_->onDecodingFailure(fmt::format("ssh: {}", err.message()));
        return;
      }
    }
  }

  void setKexResult(std::shared_ptr<KexResult> kex_result) override {
    kex_result_ = kex_result;

    connection_state_->cipher = newPacketCipher(connection_state_->direction_read,
                                                connection_state_->direction_write,
                                                kex_result.get());
    if (!initial_kex_done_) {
      initial_kex_done_ = true;
      onInitialKexDone();
    }
  }
  const KexResult& getKexResult() const override {
    return *kex_result_;
  }
  const connection_state_t& getConnectionState() const override {
    return *connection_state_;
  }

  void writeToConnection(Envoy::Buffer::Instance& buf) const override {
    return callbacks_->writeToConnection(buf);
  }

  const pomerium::extensions::ssh::CodecConfig& codecConfig() const override {
    return *config_;
  };

protected:
  virtual absl::Status onMessageDecoded(wire::SshMsg&& msg) {
    return dispatch(std::move(msg));
  }
  virtual void onInitialKexDone() {}

protected:
  Callbacks* callbacks_;

  Api::Api& api_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  AccessLog::AccessLogFileSharedPtr access_log_;

  std::unique_ptr<VersionExchanger> version_exchanger_;
  std::unique_ptr<Kex> kex_;
  std::shared_ptr<KexResult> kex_result_;
  std::unique_ptr<connection_state_t> connection_state_;

  std::string server_version_{"SSH-2.0-Envoy"};

private:
  bool version_exchange_done_{};
  bool initial_kex_done_{};
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec